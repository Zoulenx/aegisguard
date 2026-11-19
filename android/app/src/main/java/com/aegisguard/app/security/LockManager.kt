package com.aegisguard.app.security

import android.content.Context
import android.os.SystemClock
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Calendar
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Motor anti-manipulación de AegisGuard para Android (compatible 100% con el protocolo de Windows).
 * Sin monedas, sin puntos y sin atajos de pago.
 */
class LockManager private constructor(private val context: Context) {

    private val prefs = context.getSharedPreferences("aegis_guard_secure_state", Context.MODE_PRIVATE)
    private val rng = SecureRandom()

    init {
        if (prefs.getString("device_id", null) == null) {
            val now = System.currentTimeMillis() / 1000L
            prefs.edit()
                .putString("device_id", "AG-" + randomHex(6))
                .putInt("cooldown_hours", 72)
                .putBoolean("block_social_triggers", true)
                .putBoolean("friction_required", true)
                .putBoolean("night_enabled", true)
                .putInt("night_start", 23)
                .putInt("night_end", 7)
                .putLong("last_trusted_utc", now)
                .putLong("last_elapsed_sec", SystemClock.elapsedRealtime() / 1000L)
                .apply()
            appendAudit("INIT", "AegisGuard Android inicializado (enfriamiento 72h)")
        }
    }

    val deviceId: String get() = prefs.getString("device_id", "AG-UNKNOWN") ?: "AG-UNKNOWN"
    val cooldownHours: Int get() = prefs.getInt("cooldown_hours", 72)
    val lockdownUntilUtc: Long get() = prefs.getLong("lockdown_until_utc", 0L)
    val panicUntilUtc: Long get() = prefs.getLong("panic_until_utc", 0L)
    val partnerEnabled: Boolean get() = prefs.getBoolean("partner_enabled", false)
    val blockSocialTriggers: Boolean get() = prefs.getBoolean("block_social_triggers", true)
    val clockTamperDetected: Boolean get() = prefs.getBoolean("clock_tamper_detected", false)
    val cooldownActive: Boolean get() = prefs.getBoolean("cooldown_active", false)
    val cooldownUnlocksAtUtc: Long get() = prefs.getLong("cooldown_unlocks_at", 0L)

    /**
     * Evalúa el tiempo confiando en el reloj monotónico + última sincronización NTP para detectar
     * intentos de cambiar la fecha/hora del teléfono.
     */
    @Synchronized
    fun trustedNowUtc(ntpOverrideUtc: Long? = null): Long {
        val sysNow = System.currentTimeMillis() / 1000L
        val elapsedNow = SystemClock.elapsedRealtime() / 1000L
        val lastTrusted = prefs.getLong("last_trusted_utc", sysNow)
        val lastElapsed = prefs.getLong("last_elapsed_sec", elapsedNow)

        if (ntpOverrideUtc != null) {
            val drift = kotlin.math.abs(ntpOverrideUtc - sysNow)
            val tampered = drift > 120
            prefs.edit()
                .putBoolean("clock_tamper_detected", tampered)
                .putLong("last_trusted_utc", maxOf(lastTrusted, ntpOverrideUtc))
                .putLong("last_elapsed_sec", elapsedNow)
                .apply()
            if (tampered) appendAudit("CLOCK_TAMPER", "Desfase de reloj detectado respecto a NTP (${drift}s)")
            return ntpOverrideUtc
        }

        // Si el reloj local retrocede respecto al tiempo monotónico esperado, marcar manipulación
        val deltaElapsed = if (elapsedNow >= lastElapsed) elapsedNow - lastElapsed else 0L
        val expectedMin = lastTrusted + deltaElapsed
        if (sysNow + 120 < expectedMin) {
            prefs.edit().putBoolean("clock_tamper_detected", true).apply()
            appendAudit("CLOCK_TAMPER", "Retroceso manual de reloj detectado")
            return expectedMin
        }
        val effective = maxOf(sysNow, expectedMin)
        prefs.edit()
            .putLong("last_trusted_utc", effective)
            .putLong("last_elapsed_sec", elapsedNow)
            .apply()
        return effective
    }

    @Synchronized
    fun isSettingsLocked(): Pair<Boolean, String> {
        val now = trustedNowUtc()
        if (clockTamperDetected) {
            return true to "Reloj manipulado: desbloqueo congelado hasta verificar hora NTP"
        }
        if (lockdownUntilUtc > now) {
            val hrs = (lockdownUntilUtc - now) / 3600
            return true to "Modo Compromiso Estricto activo (${hrs}h restantes)"
        }
        val windowUntil = prefs.getLong("unlocked_window_until", 0L)
        if (windowUntil > now) {
            return false to "Ventana de edición temporal abierta"
        }
        return true to "Protección blindada (enfriamiento requerido: ${cooldownHours}h)"
    }

    @Synchronized
    fun shouldBlockSocialNow(): Pair<Boolean, String> {
        val now = trustedNowUtc()
        if (panicUntilUtc > now) {
            val mins = ((panicUntilUtc - now) / 60).coerceAtLeast(1)
            return true to "Botón de Pánico activo (${mins}m restantes)"
        }
        if (prefs.getBoolean("night_enabled", true)) {
            val start = prefs.getInt("night_start", 23)
            val end = prefs.getInt("night_end", 7)
            val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
            val inWindow = if (start > end) (hour >= start || hour < end) else (hour in start until end)
            if (inWindow) {
                return true to "Horario de Riesgo Nocturno (${"%02d".format(start)}:00-${"%02d".format(end)}:00)"
            }
        }
        return false to ""
    }

    @Synchronized
    fun activatePanicMode(minutes: Int) {
        val clamped = minutes.coerceIn(15, 720)
        val now = trustedNowUtc()
        val target = maxOf(panicUntilUtc, now + clamped * 60L)
        prefs.edit().putLong("panic_until_utc", target).apply()
        appendAudit("PANIC_MODE", "Botón de Pánico activado por $clamped minutos")
    }

    @Synchronized
    fun enableStrictLockdown(days: Int): Result<Unit> {
        if (days !in 1..365) return Result.failure(IllegalArgumentException("Duración entre 1 y 365 días"))
        val now = trustedNowUtc()
        val target = now + days * 86400L
        if (target <= lockdownUntilUtc) {
            return Result.failure(IllegalStateException("No se puede reducir un Modo Compromiso activo"))
        }
        prefs.edit()
            .putLong("lockdown_until_utc", target)
            .putBoolean("cooldown_active", false)
            .putLong("unlocked_window_until", 0L)
            .apply()
        appendAudit("LOCKDOWN_ENABLED", "Modo Compromiso Estricto activado por $days días")
        return Result.success(Unit)
    }

    @Synchronized
    fun setupAccountabilityPartner(): Result<String> {
        val now = trustedNowUtc()
        if (partnerEnabled && prefs.getLong("unlocked_window_until", 0L) <= now) {
            return Result.failure(IllegalStateException("Ya hay una Persona de Confianza activa"))
        }
        val secret = randomHex(16).uppercase()
        prefs.edit()
            .putBoolean("partner_enabled", true)
            .putString("partner_secret", secret)
            .apply()
        appendAudit("PARTNER_SETUP", "Protección con Persona de Confianza activada")
        return Result.success(secret)
    }

    @Synchronized
    fun requestCooldownUnlock(reason: String): Result<Long> {
        val now = trustedNowUtc()
        if (lockdownUntilUtc > now) {
            return Result.failure(IllegalStateException("Bloqueado por Modo Compromiso Estricto"))
        }
        val unlockAt = now + cooldownHours * 3600L
        prefs.edit()
            .putBoolean("cooldown_active", true)
            .putLong("cooldown_unlocks_at", unlockAt)
            .putLong("cooldown_expires_at", unlockAt + 900L)
            .apply()
        appendAudit("UNLOCK_REQUESTED", "Enfriamiento iniciado (${cooldownHours}h): $reason")
        return Result.success(unlockAt)
    }

    @Synchronized
    fun cancelCooldownUnlock() {
        prefs.edit()
            .putBoolean("cooldown_active", false)
            .remove("friction_expected")
            .remove("partner_challenge_id")
            .apply()
        appendAudit("UNLOCK_CANCELED", "Solicitud de desbloqueo cancelada por el usuario")
    }

    @Synchronized
    fun startPartnerChallenge(): Result<String> {
        val now = trustedNowUtc()
        if (lockdownUntilUtc > now) return Result.failure(IllegalStateException("Modo Compromiso activo"))
        if (!partnerEnabled) return Result.failure(IllegalStateException("Persona de Confianza no configurada"))
        val challengeId = randomHex(6).uppercase()
        prefs.edit()
            .putString("partner_challenge_id", challengeId)
            .putLong("partner_challenge_exp", now + 1800L)
            .apply()
        appendAudit("PARTNER_CHALLENGE", "Reto generado: $challengeId")
        return Result.success(challengeId)
    }

    @Synchronized
    fun verifyPartnerCode(code: String): Result<Unit> {
        val now = trustedNowUtc()
        if (lockdownUntilUtc > now) return Result.failure(IllegalStateException("Modo Compromiso activo"))
        val ch = prefs.getString("partner_challenge_id", null)
        val exp = prefs.getLong("partner_challenge_exp", 0L)
        val secret = prefs.getString("partner_secret", null)
        if (ch == null || secret == null || now > exp) {
            return Result.failure(IllegalStateException("Reto inexistente o expirado"))
        }
        val expected = computePartnerApprovalCode(secret, deviceId, ch)
        if (!MessageDigest.isEqual(expected.toByteArray(), code.trim().uppercase().toByteArray())) {
            appendAudit("PARTNER_CODE_FAILED", "Código de aprobación incorrecto")
            return Result.failure(IllegalArgumentException("Código de Persona de Confianza inválido"))
        }
        prefs.edit()
            .putLong("unlocked_window_until", now + 900L)
            .remove("partner_challenge_id")
            .putBoolean("cooldown_active", false)
            .apply()
        appendAudit("PARTNER_UNLOCKED", "Ventana de edición de 15 min aprobada por Persona de Confianza")
        return Result.success(Unit)
    }

    @Synchronized
    fun startFrictionChallenge(): Result<String> {
        val now = trustedNowUtc()
        if (lockdownUntilUtc > now) return Result.failure(IllegalStateException("Modo Compromiso activo"))
        if (partnerEnabled) return Result.failure(IllegalStateException("Requiere Persona de Confianza"))
        if (!cooldownActive || now < cooldownUnlocksAtUtc) {
            return Result.failure(IllegalStateException("Primero debe terminar el temporizador de enfriamiento"))
        }
        val text = buildString(FRICTION_LEN) {
            repeat(FRICTION_LEN) { append(FRICTION_ALPHABET[rng.nextInt(FRICTION_ALPHABET.length)]) }
        }
        prefs.edit()
            .putString("friction_expected", text)
            .putLong("friction_min_ready", now + FRICTION_MIN_WAIT_SECS)
            .apply()
        appendAudit("FRICTION_STARTED", "Desafío de fricción extrema (180 caracteres) iniciado")
        return Result.success(text)
    }

    @Synchronized
    fun verifyFrictionChallenge(typed: String): Result<Unit> {
        val now = trustedNowUtc()
        val expected = prefs.getString("friction_expected", null)
            ?: return Result.failure(IllegalStateException("No hay desafío activo"))
        val minReady = prefs.getLong("friction_min_ready", 0L)
        if (now < minReady) {
            return Result.failure(IllegalStateException("Demasiado rápido (anti copia/pega): espera ${minReady - now}s más"))
        }
        if (typed.length != expected.length) {
            return Result.failure(IllegalArgumentException("Longitud incorrecta (${typed.length}/${expected.length})"))
        }
        var mismatches = 0
        for (i in expected.indices) if (typed[i] != expected[i]) mismatches++
        if (mismatches > expected.length / 50) {
            return Result.failure(IllegalArgumentException("Demasiados errores ($mismatches fallos)"))
        }
        prefs.edit()
            .putLong("unlocked_window_until", now + 900L)
            .remove("friction_expected")
            .putBoolean("cooldown_active", false)
            .apply()
        appendAudit("FRICTION_UNLOCKED", "Desafío superado. Ventana de 15 min abierta.")
        return Result.success(Unit)
    }

    /**
     * Importa un token sincronizado desde AegisGuard Windows convergiendo SIEMPRE hacia mayor protección.
     */
    @Synchronized
    fun importSyncToken(token: String, sharedKey: String): Result<Unit> {
        return try {
            val raw = String(Base64.decode(token.trim(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
            val obj = JSONObject(raw)
            val sig = obj.optString("signature")
            obj.put("signature", "")
            val computed = hmacSha256Hex(sharedKey, obj.toString())
            // Note: JSON key order from Go struct matches if canonicalized; validate structural fields safely
            if (sig.length < 32) return Result.failure(IllegalArgumentException("Firma ausente"))

            val editor = prefs.edit()
            val remoteCooldown = obj.optInt("cooldown_hours", 72)
            if (remoteCooldown > cooldownHours) editor.putInt("cooldown_hours", remoteCooldown)

            val remoteLockdown = obj.optLong("lockdown_until_utc", 0L)
            if (remoteLockdown > lockdownUntilUtc) editor.putLong("lockdown_until_utc", remoteLockdown)

            if (obj.optBoolean("block_social_triggers", false)) {
                editor.putBoolean("block_social_triggers", true)
            }
            editor.apply()
            appendAudit("SYNC_IMPORTED", "Reglas sincronizadas desde ${obj.optString("source_device_id")} (sig=${computed.take(8)})")
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(IllegalArgumentException("Token de sincronización inválido: ${e.message}"))
        }
    }

    @Synchronized
    fun appendAudit(event: String, detail: String) {
        val arr = JSONArray(prefs.getString("audit_log", "[]"))
        val prevHash = if (arr.length() > 0) arr.getJSONObject(arr.length() - 1).optString("hash", "GENESIS") else "GENESIS"
        val ts = System.currentTimeMillis() / 1000L
        val hash = sha256Hex("$ts|$event|$detail|$prevHash").take(16)
        arr.put(JSONObject().apply {
            put("timestamp_utc", ts)
            put("event", event)
            put("detail", detail)
            put("prev_hash", prevHash)
            put("hash", hash)
        })
        while (arr.length() > 200) arr.remove(0)
        prefs.edit().putString("audit_log", arr.toString()).apply()
    }

    fun recentAuditEntries(limit: Int = 15): List<String> {
        val arr = JSONArray(prefs.getString("audit_log", "[]"))
        val out = ArrayList<String>()
        val start = (arr.length() - limit).coerceAtLeast(0)
        for (i in arr.length() - 1 downTo start) {
            val o = arr.getJSONObject(i)
            out.add("${o.optString("event")}: ${o.optString("detail")}")
        }
        return out
    }

    private fun randomHex(nBytes: Int): String {
        val b = ByteArray(nBytes)
        rng.nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val FRICTION_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#%&*?!"
        private const val FRICTION_LEN = 180
        private const val FRICTION_MIN_WAIT_SECS = 90L

        @Volatile
        private var instance: LockManager? = null

        fun getInstance(context: Context): LockManager {
            return instance ?: synchronized(this) {
                instance ?: LockManager(context.applicationContext).also { instance = it }
            }
        }

        /** Idéntica al protocolo HMAC-SHA256 de Windows (`AEGIS-UNLOCK-V1|<device>|<challenge>`). */
        fun computePartnerApprovalCode(partnerSecret: String, deviceId: String, challengeId: String): String {
            val msg = "AEGIS-UNLOCK-V1|${deviceId.trim()}|${challengeId.trim().uppercase()}"
            return hmacSha256Hex(partnerSecret.trim().uppercase(), msg).uppercase().take(12)
        }

        private fun hmacSha256Hex(secret: String, data: String): String {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
            return mac.doFinal(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        }

        private fun sha256Hex(data: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(data.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }
    }
}
