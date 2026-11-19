package com.aegisguard.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.aegisguard.app.filter.DomainFilter
import com.aegisguard.app.security.LockManager
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * VPN Local de AegisGuard (sin servidor externo, 100% en el dispositivo).
 * Intercepta todo el tráfico DNS del teléfono (apps + navegadores), bloquea pornografía,
 * servidores DoH de evasión y redes sociales durante el Botón de Pánico / Horario Nocturno,
 * y reenvía consultas limpias a Cloudflare for Families (1.1.1.3).
 */
class AegisVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var workerThread: Thread? = null

    private lateinit var domainFilter: DomainFilter
    private lateinit var lockManager: LockManager

    override fun onCreate() {
        super.onCreate()
        domainFilter = DomainFilter.getInstance(this)
        lockManager = LockManager.getInstance(this)
        domainFilter.socialBlockProvider = { lockManager.shouldBlockSocialNow() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            val (locked, _) = lockManager.isSettingsLocked()
            if (!locked) {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            // Ignora solicitud de detención mientras el bloqueo esté activo
            return START_STICKY
        }

        startForeground(NOTIF_ID, buildNotification())
        if (running.compareAndSet(false, true)) {
            startVpnTunnel()
        }
        return START_STICKY
    }

    private fun startVpnTunnel() {
        val builder = Builder()
            .setSession("AegisGuard Protección DNS")
            .setMtu(1500)
            .addAddress(VPN_CLIENT_IP, 32)
            .addDnsServer(VPN_DNS_IP)
            .addRoute(VPN_DNS_IP, 32) // Enruta todo el DNS a través de nuestro túnel local sin ralentizar el resto del tráfico
            .setBlocking(true)

        // Excluir la propia app para permitir NTP y consultas DNS upstream protegidas
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        vpnInterface = builder.establish() ?: run {
            running.set(false)
            return
        }

        workerThread = Thread({ runPacketLoop() }, "AegisGuard-DNS-VPN").apply { start() }
    }

    private fun runPacketLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val input = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val buffer = ByteArray(32767)

        while (running.get()) {
            val len = try {
                input.read(buffer)
            } catch (_: Exception) {
                break
            }
            if (len < 28) continue

            // Verificar IPv4 (versión 4) y protocolo UDP (17)
            val version = (buffer[0].toInt() ushr 4) and 0x0F
            if (version != 4) continue
            val ihl = (buffer[0].toInt() and 0x0F) * 4
            val protocol = buffer[9].toInt() and 0xFF
            if (protocol != 17 || len < ihl + 8) continue

            val dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
            if (dstPort != 53) continue

            val dnsStart = ihl + 8
            val dnsLen = len - dnsStart
            if (dnsLen < 17) continue

            val dnsQuery = buffer.copyOfRange(dnsStart, len)
            val dnsResp = processDnsQuery(dnsQuery) ?: continue

            val replyPacket = buildIpv4UdpReply(
                origPacket = buffer,
                ihl = ihl,
                payload = dnsResp
            )
            try {
                output.write(replyPacket)
            } catch (_: Exception) {
                break
            }
        }
    }

    private fun processDnsQuery(query: ByteArray): ByteArray? {
        val parsed = parseDnsQuestion(query) ?: return null
        val (domain, qtype, qEnd) = parsed
        val decision = domainFilter.evaluate(domain)

        return when (decision.action) {
            "BLOCK" -> {
                blockedDnsCount.incrementAndGet()
                lockManager.appendAudit("DNS_BLOCK", "$domain (${decision.reason})")
                buildBlockedDnsResponse(query, qtype, qEnd)
            }
            else -> {
                allowedDnsCount.incrementAndGet()
                forwardToFamilyUpstream(query)
            }
        }
    }

    private fun forwardToFamilyUpstream(query: ByteArray): ByteArray? {
        for (ip in UPSTREAM_DNS) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protect(socket) // Evita bucle infinito en el túnel VPN
                socket.soTimeout = 2500
                val addr = InetAddress.getByName(ip)
                socket.send(DatagramPacket(query, query.size, addr, 53))
                val respBuf = ByteArray(2048)
                val respPkt = DatagramPacket(respBuf, respBuf.size)
                socket.receive(respPkt)
                return respBuf.copyOf(respPkt.length)
            } catch (_: Exception) {
                // Intenta el siguiente upstream familiar
            } finally {
                socket?.close()
            }
        }
        return null
    }

    private fun parseDnsQuestion(pkt: ByteArray): Triple<String, Int, Int>? {
        if (pkt.size < 17) return null
        var off = 12
        val labels = ArrayList<String>()
        while (off < pkt.size) {
            val len = pkt[off].toInt() and 0xFF
            off++
            if (len == 0) break
            if (len > 63 || off + len > pkt.size) return null
            labels.add(String(pkt, off, len, Charsets.US_ASCII).lowercase())
            off += len
        }
        if (off + 4 > pkt.size) return null
        val qtype = ((pkt[off].toInt() and 0xFF) shl 8) or (pkt[off + 1].toInt() and 0xFF)
        return Triple(labels.joinToString("."), qtype, off + 4)
    }

    private fun buildBlockedDnsResponse(req: ByteArray, qtype: Int, qEnd: Int): ByteArray {
        val isA = qtype == 1
        val isAAAA = qtype == 28
        if (!isA && !isAAAA) {
            val out = req.copyOf(qEnd)
            out[2] = 0x81.toByte()
            out[3] = 0x83.toByte() // NXDOMAIN
            out[6] = 0; out[7] = 0; out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0
            return out
        }
        val rdataLen = if (isA) 4 else 16
        val out = ByteArray(qEnd + 12 + rdataLen)
        System.arraycopy(req, 0, out, 0, qEnd)
        out[2] = 0x81.toByte()
        out[3] = 0x80.toByte()
        out[4] = 0; out[5] = 1
        out[6] = 0; out[7] = 1
        out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0

        var p = qEnd
        out[p++] = 0xC0.toByte(); out[p++] = 0x0C // Pointer to QNAME
        out[p++] = (qtype ushr 8).toByte(); out[p++] = (qtype and 0xFF).toByte()
        out[p++] = 0; out[p++] = 1 // Class IN
        out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 60 // TTL 60s
        out[p++] = 0; out[p] = rdataLen.toByte()
        // Remaining bytes stay 0x00 -> 0.0.0.0 or ::
        return out
    }

    private fun buildIpv4UdpReply(origPacket: ByteArray, ihl: Int, payload: ByteArray): ByteArray {
        val totalLen = 20 + 8 + payload.size
        val pkt = ByteBuffer.allocate(totalLen)

        // IPv4 Header (20 bytes)
        pkt.put(0x45.toByte()) // Version 4, IHL 5
        pkt.put(0) // TOS
        pkt.putShort(totalLen.toShort())
        pkt.putShort(0) // ID
        pkt.putShort(0) // Flags/Frag
        pkt.put(64.toByte()) // TTL
        pkt.put(17.toByte()) // UDP
        pkt.putShort(0) // Checksum placeholder
        // Swap src and dst IP
        pkt.put(origPacket, 16, 4) // new src = old dst
        pkt.put(origPacket, 12, 4) // new dst = old src

        val ipHeader = pkt.array()
        val ipChecksum = ipv4Checksum(ipHeader, 0, 20)
        ipHeader[10] = (ipChecksum ushr 8).toByte()
        ipHeader[11] = (ipChecksum and 0xFF).toByte()

        // UDP Header (8 bytes) — swap src & dst ports
        val origSrcPort = ((origPacket[ihl].toInt() and 0xFF) shl 8) or (origPacket[ihl + 1].toInt() and 0xFF)
        val origDstPort = ((origPacket[ihl + 2].toInt() and 0xFF) shl 8) or (origPacket[ihl + 3].toInt() and 0xFF)
        pkt.putShort(origDstPort.toShort())
        pkt.putShort(origSrcPort.toShort())
        pkt.putShort((8 + payload.size).toShort())
        pkt.putShort(0) // UDP checksum optional in IPv4

        pkt.put(payload)
        return pkt.array()
    }

    private fun ipv4Checksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length) {
            val word = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun buildNotification(): Notification {
        val channelId = "aegisguard_vpn_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                channelId,
                "Protección VPN Local AegisGuard",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("AegisGuard Protección Activa")
            .setContentText("Filtrando sitios adultos, DoH y redes sociales en tiempo real")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    private fun stopVpn() {
        running.set(false)
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        workerThread?.interrupt()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.aegisguard.app.STOP_VPN"
        private const val NOTIF_ID = 1001
        private const val VPN_CLIENT_IP = "10.111.222.1"
        private const val VPN_DNS_IP = "10.111.222.2"
        private val UPSTREAM_DNS = listOf("1.1.1.3", "185.228.168.168")

        val blockedDnsCount = AtomicLong(0)
        val allowedDnsCount = AtomicLong(0)
    }
}
