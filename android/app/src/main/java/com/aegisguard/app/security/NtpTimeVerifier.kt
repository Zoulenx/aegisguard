package com.aegisguard.app.security

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Cliente SNTP (RFC 4330) ligero para verificar la hora real UTC
 * e impedir que adelantar o atrasar el reloj del teléfono burle los temporizadores.
 */
object NtpTimeVerifier {
    private const val NTP_EPOCH_OFFSET = 2208988800L
    private val SERVERS = listOf("time.cloudflare.com", "time.google.com", "pool.ntp.org")

    fun queryVerifiedUtcSeconds(timeoutMs: Int = 2000): Pair<Long, Boolean> {
        for (host in SERVERS) {
            try {
                val addr = InetAddress.getByName(host)
                val req = ByteArray(48).apply { this[0] = 0x1B }
                DatagramSocket().use { socket ->
                    socket.soTimeout = timeoutMs
                    socket.send(DatagramPacket(req, req.size, addr, 123))
                    val resp = ByteArray(48)
                    val packet = DatagramPacket(resp, resp.size)
                    socket.receive(packet)
                    val secs = ((resp[40].toLong() and 0xFF) shl 24) or
                        ((resp[41].toLong() and 0xFF) shl 16) or
                        ((resp[42].toLong() and 0xFF) shl 8) or
                        (resp[43].toLong() and 0xFF)
                    if (secs >= NTP_EPOCH_OFFSET) {
                        return Pair(secs - NTP_EPOCH_OFFSET, true)
                    }
                }
            } catch (_: Exception) {
                // Try next NTP server
            }
        }
        return Pair(System.currentTimeMillis() / 1000L, false)
    }
}
