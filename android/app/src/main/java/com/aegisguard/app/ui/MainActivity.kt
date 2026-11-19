package com.aegisguard.app.ui

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import com.aegisguard.app.admin.AegisDeviceAdminReceiver
import com.aegisguard.app.filter.DomainFilter
import com.aegisguard.app.filter.SemanticContentFilter
import com.aegisguard.app.security.LockManager
import com.aegisguard.app.security.NtpTimeVerifier
import com.aegisguard.app.vpn.AegisVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var lockManager: LockManager
    private lateinit var semanticFilter: SemanticContentFilter
    private lateinit var domainFilter: DomainFilter

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) {
            startAegisVpn()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lockManager = LockManager.getInstance(this)
        semanticFilter = SemanticContentFilter.getInstance(this)
        domainFilter = DomainFilter.getInstance(this)

        // Verificar hora real NTP en segundo plano para detectar manipulación de reloj
        lifecycleScope.launch(Dispatchers.IO) {
            val (utc, fromNet) = NtpTimeVerifier.queryVerifiedUtcSeconds()
            if (fromNet) lockManager.trustedNowUtc(utc)
        }

        setContent {
            AegisDashboard(
                lockManager = lockManager,
                semanticFilter = semanticFilter,
                domainFilter = domainFilter,
                isDeviceOwner = AegisDeviceAdminReceiver.isDeviceOwner(this),
                onStartVpn = { requestAndStartVpn() },
                onOpenAccessibility = { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) },
                onRequestDeviceAdmin = {
                    val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                        putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, AegisDeviceAdminReceiver.componentName(this@MainActivity))
                        putExtra(
                            DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                            "Impide la desinstalación rápida de AegisGuard durante un impulso."
                        )
                    }
                    startActivity(intent)
                },
                onApplyDeviceOwner = {
                    AegisDeviceAdminReceiver.applyStrictDeviceOwnerPolicies(this)
                }
            )
        }
    }

    private fun requestAndStartVpn() {
        val prep = VpnService.prepare(this)
        if (prep != null) {
            vpnPermissionLauncher.launch(prep)
        } else {
            startAegisVpn()
        }
    }

    private fun startAegisVpn() {
        val intent = Intent(this, AegisVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }
}

@Composable
private fun AegisDashboard(
    lockManager: LockManager,
    semanticFilter: SemanticContentFilter,
    domainFilter: DomainFilter,
    isDeviceOwner: Boolean,
    onStartVpn: () -> Unit,
    onOpenAccessibility: () -> Unit,
    onRequestDeviceAdmin: () -> Unit,
    onApplyDeviceOwner: () -> Result<String>
) {
    var statusMsg by remember { mutableStateOf("") }
    var refreshTick by remember { mutableIntStateOf(0) }
    var testInput by remember { mutableStateOf("") }
    var testOutput by remember { mutableStateOf("") }
    var unlockReason by remember { mutableStateOf("") }
    var partnerChallengeId by remember { mutableStateOf("") }
    var partnerCode by remember { mutableStateOf("") }
    var frictionTarget by remember { mutableStateOf("") }
    var frictionTyped by remember { mutableStateOf("") }
    var syncKey by remember { mutableStateOf("") }
    var syncToken by remember { mutableStateOf("") }

    val (locked, lockReason) = remember(refreshTick) { lockManager.isSettingsLocked() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0B1120))
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Header
        Text("AegisGuard Android", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Text(
            "ID: ${lockManager.deviceId} · Sin monedas · Sin atajos · Windows ↔ Android",
            color = Color(0xFF9CA3AF),
            fontSize = 12.sp
        )

        // Estado & Permisos Clave
        SectionCard("1. Activación de Escudos") {
            Text(
                text = if (locked) "Estado: BLINDADO ($lockReason)" else "Estado: Ventana temporal abierta",
                color = if (locked) Color(0xFF34D399) else Color(0xFFFBBF24),
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "DNS Bloqueados: ${AegisVpnService.blockedDnsCount.get()} · Device Owner: ${if (isDeviceOwner) "ACTIVO" else "No activado"}",
                color = Color(0xFF9CA3AF),
                fontSize = 12.sp
            )
            Spacer(Modifier.height(8.dp))
            Button(onClick = onStartVpn, modifier = Modifier.fillMaxWidth()) {
                Text("Activar VPN Local (Bloqueo Web + SafeSearch)")
            }
            OutlinedButton(onClick = onOpenAccessibility, modifier = Modifier.fillMaxWidth()) {
                Text("Activar Accesibilidad (Filtro en Instagram/TikTok/X/Telegram)", color = Color.White)
            }
            OutlinedButton(onClick = onRequestDeviceAdmin, modifier = Modifier.fillMaxWidth()) {
                Text("Activar Administrador de Dispositivo", color = Color.White)
            }
            if (isDeviceOwner) {
                Button(
                    onClick = {
                        onApplyDeviceOwner()
                            .onSuccess { statusMsg = it }
                            .onFailure { statusMsg = it.message ?: "Error" }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Aplicar Blindaje Total Device Owner")
                }
            }
        }

        // Botón de Pánico
        SectionCard("2. Botón de Pánico (Anti-Recaída)") {
            Text(
                "Bloquea de inmediato todas las redes sociales y navegadores de riesgo sin poder cancelarlo antes.",
                color = Color(0xFF9CA3AF),
                fontSize = 12.sp
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        lockManager.activatePanicMode(30)
                        statusMsg = "Botón de Pánico activado por 30 minutos."
                        refreshTick++
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    modifier = Modifier.weight(1f)
                ) { Text("30 min") }
                Button(
                    onClick = {
                        lockManager.activatePanicMode(60)
                        statusMsg = "Botón de Pánico activado por 60 minutos."
                        refreshTick++
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    modifier = Modifier.weight(1f)
                ) { Text("60 min") }
                Button(
                    onClick = {
                        lockManager.activatePanicMode(180)
                        statusMsg = "Botón de Pánico activado por 3 horas."
                        refreshTick++
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    modifier = Modifier.weight(1f)
                ) { Text("3 horas") }
            }
        }

        // Modo Compromiso y Persona de Confianza
        SectionCard("3. Blindaje Irreversible y Persona de Confianza") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        lockManager.enableStrictLockdown(7)
                            .onSuccess { statusMsg = "Modo Compromiso Estricto activado por 7 días." }
                            .onFailure { statusMsg = it.message ?: "Error" }
                        refreshTick++
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                    modifier = Modifier.weight(1f)
                ) { Text("Compromiso 7d") }
                Button(
                    onClick = {
                        lockManager.enableStrictLockdown(30)
                            .onSuccess { statusMsg = "Modo Compromiso Estricto activado por 30 días." }
                            .onFailure { statusMsg = it.message ?: "Error" }
                        refreshTick++
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                    modifier = Modifier.weight(1f)
                ) { Text("Compromiso 30d") }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    lockManager.setupAccountabilityPartner()
                        .onSuccess { secret -> statusMsg = "ENTREGA ESTA CLAVE SOLO A TU PERSONA DE CONFIANZA: $secret" }
                        .onFailure { statusMsg = it.message ?: "Error" }
                    refreshTick++
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text("Configurar Persona de Confianza (HMAC)", color = Color.White) }
        }

        // Desbloqueo con Enfriamiento + Fricción Extrema / Persona de Confianza
        SectionCard("4. Desbloqueo Difícil (Enfriamiento + Fricción)") {
            OutlinedTextField(
                value = unlockReason,
                onValueChange = { unlockReason = it },
                label = { Text("Motivo para iniciar enfriamiento (${lockManager.cooldownHours}h)") },
                modifier = Modifier.fillMaxWidth()
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        lockManager.requestCooldownUnlock(unlockReason)
                            .onSuccess { statusMsg = "Enfriamiento iniciado. No se puede acelerar." }
                            .onFailure { statusMsg = it.message ?: "Error" }
                        refreshTick++
                    },
                    modifier = Modifier.weight(1f)
                ) { Text("Iniciar Enfriamiento") }
                OutlinedButton(
                    onClick = {
                        lockManager.cancelCooldownUnlock()
                        frictionTarget = ""
                        statusMsg = "Solicitud cancelada. Protección firme."
                        refreshTick++
                    },
                    modifier = Modifier.weight(1f)
                ) { Text("Cancelar (1 clic)", color = Color(0xFF34D399)) }
            }

            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    lockManager.startFrictionChallenge()
                        .onSuccess { frictionTarget = it; frictionTyped = "" }
                        .onFailure { statusMsg = it.message ?: "Error" }
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text("Iniciar Desafío de Fricción (180 chars)", color = Color.White) }

            if (frictionTarget.isNotEmpty()) {
                Text(
                    text = frictionTarget,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = Color(0xFFFBBF24),
                    modifier = Modifier.padding(vertical = 6.dp)
                )
                OutlinedTextField(
                    value = frictionTyped,
                    onValueChange = { newVal ->
                        // Bloquea pegado masivo desde el portapapeles (máx +2 caracteres por pulsación)
                        if (newVal.length - frictionTyped.length <= 2) {
                            frictionTyped = newVal
                        } else {
                            statusMsg = "Pegar está bloqueado: debes escribir manualmente."
                        }
                    },
                    label = { Text("Escribe manualmente (${frictionTyped.length}/180)") },
                    modifier = Modifier.fillMaxWidth()
                )
                Button(onClick = {
                    lockManager.verifyFrictionChallenge(frictionTyped)
                        .onSuccess { statusMsg = "Desafío superado. Ventana de 15 min abierta."; frictionTarget = "" }
                        .onFailure { statusMsg = it.message ?: "Error" }
                    refreshTick++
                }) { Text("Verificar Desafío") }
            }

            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    lockManager.startPartnerChallenge()
                        .onSuccess { partnerChallengeId = it }
                        .onFailure { statusMsg = it.message ?: "Error" }
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text("Generar Reto para Persona de Confianza", color = Color.White) }
            if (partnerChallengeId.isNotEmpty()) {
                Text("Dispositivo: ${lockManager.deviceId} | Reto: $partnerChallengeId", color = Color(0xFF38BDF8), fontSize = 12.sp)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = partnerCode,
                    onValueChange = { partnerCode = it },
                    label = { Text("Código de 12 caracteres") },
                    modifier = Modifier.weight(1f)
                )
                Button(onClick = {
                    lockManager.verifyPartnerCode(partnerCode)
                        .onSuccess { statusMsg = "Aprobado por Persona de Confianza (15 min)." }
                        .onFailure { statusMsg = it.message ?: "Error" }
                    refreshTick++
                }) { Text("Validar") }
            }
        }

        // Simulador y Sincronización Windows <-> Android
        SectionCard("5. Probar Filtro y Sincronizar con Windows") {
            OutlinedTextField(
                value = testInput,
                onValueChange = { testInput = it },
                label = { Text("Prueba texto ofuscado (ej: p0rn0, p o r n, pornhub.com)") },
                modifier = Modifier.fillMaxWidth()
            )
            Button(onClick = {
                val tv = semanticFilter.analyze(testInput)
                val dv = domainFilter.evaluate(testInput)
                testOutput = if (tv.blocked || dv.action == "BLOCK") {
                    "BLOQUEADO -> ${tv.reason.ifEmpty { dv.reason }}"
                } else {
                    "PERMITIDO (score=${tv.score}, dns=${dv.action})"
                }
            }) { Text("Probar Motor") }
            if (testOutput.isNotEmpty()) Text(testOutput, color = Color(0xFFFCA5A5), fontSize = 12.sp)

            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = syncKey,
                onValueChange = { syncKey = it },
                label = { Text("Clave compartida con Windows") },
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = syncToken,
                onValueChange = { syncToken = it },
                label = { Text("Token de sincronización exportado desde Windows") },
                modifier = Modifier.fillMaxWidth()
            )
            Button(onClick = {
                lockManager.importSyncToken(syncToken, syncKey)
                    .onSuccess { statusMsg = "Reglas sincronizadas desde Windows correctamente." }
                    .onFailure { statusMsg = it.message ?: "Error" }
                refreshTick++
            }) { Text("Importar Reglas de Windows") }
        }

        if (statusMsg.isNotEmpty()) {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B))) {
                Text(statusMsg, color = Color(0xFF38BDF8), modifier = Modifier.padding(14.dp), fontSize = 13.sp)
            }
        }
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF111827)),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            content()
        }
    }
}
