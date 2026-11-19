package com.aegisguard.app.accessibility

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.os.Bundle
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.aegisguard.app.filter.DomainFilter
import com.aegisguard.app.filter.SemanticContentFilter
import com.aegisguard.app.security.LockManager
import com.aegisguard.app.ui.BlockOverlayActivity

/**
 * Servicio de Accesibilidad de AegisGuard:
 * 1. Filtra búsquedas sexuales (incluyendo jerga/leetspeak) DENTRO de apps nativas
 *    (Instagram, TikTok, X, Reddit, Telegram, YouTube, Facebook, Snapchat, navegadores).
 * 2. Bloquea pestañas disparadoras (Reels, Explorar, Shorts, Para ti) sin romper los chats.
 * 3. Bloquea redes sociales enteras durante el Botón de Pánico o el Horario Nocturno.
 * 4. Escudo Anti-Manipulación: impide entrar a Ajustes para desactivar Accesibilidad,
 *    VPN, Admin de Dispositivo o desinstalar AegisGuard mientras el bloqueo esté activo.
 */
class ContentGuardAccessibilityService : AccessibilityService() {

    private lateinit var semanticFilter: SemanticContentFilter
    private lateinit var domainFilter: DomainFilter
    private lateinit var lockManager: LockManager

    private var lastInterventionMs = 0L

    override fun onServiceConnected() {
        super.onServiceConnected()
        semanticFilter = SemanticContentFilter.getInstance(this)
        domainFilter = DomainFilter.getInstance(this)
        lockManager = LockManager.getInstance(this)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName) return

        // 1. Escudo Anti-Manipulación de Ajustes de Android
        if (SETTINGS_PACKAGES.contains(pkg)) {
            guardSettingsAgainstTampering()
            return
        }

        // 2. Bloqueo total de redes sociales durante Botón de Pánico u Horario Nocturno
        val socialApp = domainFilter.getSocialAppForPackage(pkg)
        if (socialApp != null) {
            val (blockSocial, reason) = lockManager.shouldBlockSocialNow()
            if (blockSocial) {
                triggerIntervention(
                    sourceApp = socialApp.name,
                    reason = "$reason — ${socialApp.name} bloqueada temporalmente",
                    goHome = true
                )
                return
            }
        }

        // 3. Inspección en tiempo real de cajas de texto / barras de búsqueda (Instagram, TikTok, X, Telegram, Chrome...)
        if (event.eventType == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED ||
            event.eventType == AccessibilityEvent.TYPE_VIEW_FOCUSED
        ) {
            val typedText = event.text?.joinToString(" ") ?: ""
            if (typedText.length >= 3) {
                val verdict = semanticFilter.analyze(typedText)
                if (verdict.blocked) {
                    clearNodeText(event.source)
                    triggerIntervention(
                        sourceApp = socialApp?.name ?: pkg,
                        reason = "Búsqueda explícita interceptada en ${socialApp?.name ?: pkg}: ${verdict.reason}",
                        goHome = false
                    )
                    return
                }
            }
        }

        // 4. Inspección del árbol visible para pestañas disparadoras (Reels / Explorar / Shorts) y contenido explícito
        val root = rootInActiveWindow ?: return
        try {
            if (socialApp != null && lockManager.blockSocialTriggers) {
                if (detectSelectedTriggerTab(root, socialApp.triggerTabs)) {
                    triggerIntervention(
                        sourceApp = socialApp.name,
                        reason = "Pestaña disparadora bloqueada en ${socialApp.name} (Reels / Explorar / Shorts)",
                        goHome = false
                    )
                    return
                }
            }

            // Analizar encabezados, URLs de navegadores y campos de búsqueda visibles en pantalla
            val extracted = collectHighSignalText(root, maxNodes = 70)
            if (extracted.isNotEmpty()) {
                val verdict = semanticFilter.analyze(extracted)
                if (verdict.blocked) {
                    triggerIntervention(
                        sourceApp = socialApp?.name ?: pkg,
                        reason = "Contenido explícito detectado en ${socialApp?.name ?: pkg}: ${verdict.reason}",
                        goHome = false
                    )
                }
            }
        } finally {
            @Suppress("DEPRECATION")
            root.recycle()
        }
    }

    private fun guardSettingsAgainstTampering() {
        val (locked, lockReason) = lockManager.isSettingsLocked()
        if (!locked) return

        val root = rootInActiveWindow ?: return
        try {
            val text = collectHighSignalText(root, maxNodes = 90).lowercase()
            val mentionsSelf = text.contains("aegisguard")
            val mentionsDangerousSection = DANGEROUS_SETTINGS_TERMS.any { text.contains(it) }
            if (mentionsSelf && mentionsDangerousSection) {
                lockManager.appendAudit("TAMPER_BLOCKED", "Intento de desactivar protección en Ajustes bloqueado")
                triggerIntervention(
                    sourceApp = "Ajustes del Sistema",
                    reason = "Desactivación bloqueada — $lockReason",
                    goHome = true
                )
            }
        } finally {
            @Suppress("DEPRECATION")
            root.recycle()
        }
    }

    private fun detectSelectedTriggerTab(node: AccessibilityNodeInfo, triggerTabs: Set<String>): Boolean {
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(node)
        var visited = 0
        while (queue.isNotEmpty() && visited < 80) {
            val cur = queue.removeFirst()
            visited++
            val label = (cur.contentDescription?.toString() ?: cur.text?.toString() ?: "").trim().lowercase()
            if (label.isNotEmpty() && cur.isSelected && triggerTabs.any { label == it || label.startsWith("$it ") }) {
                return true
            }
            for (i in 0 until cur.childCount) {
                cur.getChild(i)?.let { queue.add(it) }
            }
        }
        return false
    }

    private fun collectHighSignalText(root: AccessibilityNodeInfo, maxNodes: Int): String {
        val sb = StringBuilder()
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        var visited = 0
        while (queue.isNotEmpty() && visited < maxNodes && sb.length < 1500) {
            val cur = queue.removeFirst()
            visited++
            val cls = cur.className?.toString() ?: ""
            val isInputOrText = cls.contains("EditText") || cls.contains("TextView") || cls.contains("WebView")
            if (isInputOrText) {
                cur.text?.toString()?.takeIf { it.length in 2..200 }?.let {
                    sb.append(it).append(' ')
                }
            }
            for (i in 0 until cur.childCount) {
                cur.getChild(i)?.let { queue.add(it) }
            }
        }
        return sb.toString()
    }

    private fun clearNodeText(node: AccessibilityNodeInfo?) {
        if (node == null) return
        try {
            val args = Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, "")
            }
            node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        } catch (_: Exception) {
        }
    }

    private fun triggerIntervention(sourceApp: String, reason: String, goHome: Boolean) {
        val now = System.currentTimeMillis()
        if (now - lastInterventionMs < 1500L) return
        lastInterventionMs = now

        lockManager.appendAudit("APP_BLOCK", "$sourceApp -> $reason")
        performGlobalAction(if (goHome) GLOBAL_ACTION_HOME else GLOBAL_ACTION_BACK)

        val intent = Intent(this, BlockOverlayActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            putExtra(BlockOverlayActivity.EXTRA_REASON, reason)
            putExtra(BlockOverlayActivity.EXTRA_SOURCE_APP, sourceApp)
        }
        startActivity(intent)
    }

    override fun onInterrupt() {}

    companion object {
        private val SETTINGS_PACKAGES = setOf(
            "com.android.settings",
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.samsung.android.packageinstaller"
        )
        private val DANGEROUS_SETTINGS_TERMS = listOf(
            "desinstalar", "uninstall", "forzar detencion", "forzar detención", "force stop",
            "accesibilidad", "accessibility", "vpn", "administrador", "device admin",
            "borrar datos", "clear storage", "clear data", "eliminar", "desactivar", "disable"
        )
    }
}
