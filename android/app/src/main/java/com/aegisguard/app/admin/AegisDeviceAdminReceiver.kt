package com.aegisguard.app.admin

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.UserManager
import com.aegisguard.app.security.LockManager

/**
 * Receptor de Administrador / Propietario de Dispositivo (Device Owner).
 * Cuando se activa como Device Owner por USB (ADB, sin root), Android prohíbe a nivel de sistema:
 * - Desinstalar AegisGuard
 * - Desactivar la VPN Always-On
 * - Cambiar la fecha y hora del sistema
 * - Arrancar en Modo Seguro para saltarse el filtro
 * - Crear usuarios secundarios sin filtro
 */
class AegisDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        val lockMgr = LockManager.getInstance(context)
        val (locked, reason) = lockMgr.isSettingsLocked()
        return if (locked) {
            lockMgr.appendAudit("ADMIN_DISABLE_ATTEMPT", "Intento de desactivar Administrador bloqueado")
            "AegisGuard está bloqueado ($reason). Completa el enfriamiento o usa tu Persona de Confianza."
        } else {
            "Ventana de desbloqueo temporal abierta. Puedes modificar AegisGuard ahora."
        }
    }

    companion object {
        fun componentName(context: Context): ComponentName =
            ComponentName(context.applicationContext, AegisDeviceAdminReceiver::class.java)

        fun isDeviceOwner(context: Context): Boolean {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            return dpm.isDeviceOwnerApp(context.packageName)
        }

        fun isAdminActive(context: Context): Boolean {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            return dpm.isAdminActive(componentName(context))
        }

        /**
         * Aplica todas las protecciones de nivel de sistema disponibles en modo Device Owner.
         */
        fun applyStrictDeviceOwnerPolicies(context: Context): Result<String> {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            val admin = componentName(context)
            if (!dpm.isDeviceOwnerApp(context.packageName)) {
                return Result.failure(
                    IllegalStateException("AegisGuard aún no es Device Owner. Ejecuta scripts/activate-device-owner vía ADB.")
                )
            }

            // 1. Impedir desinstalación de AegisGuard
            dpm.setUninstallBlocked(admin, context.packageName, true)

            // 2. Impedir cambiar fecha/hora, arrancar en Modo Seguro, crear usuarios secundarios y apps desconocidas
            dpm.addUserRestriction(admin, UserManager.DISALLOW_CONFIG_DATE_TIME)
            dpm.addUserRestriction(admin, UserManager.DISALLOW_SAFE_BOOT)
            dpm.addUserRestriction(admin, UserManager.DISALLOW_ADD_USER)
            dpm.addUserRestriction(admin, UserManager.DISALLOW_CONFIG_VPN)

            // 3. Fijar AegisVpnService como VPN Always-On con bloqueo de conexiones sin VPN (lockdown = true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                try {
                    dpm.setAlwaysOnVpnPackage(admin, context.packageName, true, emptySet())
                } catch (_: Exception) {
                }
            }

            LockManager.getInstance(context)
                .appendAudit("DEVICE_OWNER_HARDENED", "Políticas Device Owner aplicadas (anti-desinstalación + VPN obligatoria + sin Modo Seguro)")
            return Result.success("Blindaje Device Owner activado correctamente.")
        }

        /**
         * Solo permite retirar políticas Device Owner cuando el LockManager confirma ventana de desbloqueo abierta.
         */
        fun releaseDeviceOwnerPoliciesIfUnlocked(context: Context): Result<Unit> {
            val lockMgr = LockManager.getInstance(context)
            val (locked, reason) = lockMgr.isSettingsLocked()
            if (locked) {
                return Result.failure(IllegalStateException("No permitido mientras el bloqueo está activo: $reason"))
            }
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            val admin = componentName(context)
            if (dpm.isDeviceOwnerApp(context.packageName)) {
                dpm.setUninstallBlocked(admin, context.packageName, false)
                dpm.clearUserRestriction(admin, UserManager.DISALLOW_CONFIG_DATE_TIME)
                dpm.clearUserRestriction(admin, UserManager.DISALLOW_SAFE_BOOT)
                dpm.clearUserRestriction(admin, UserManager.DISALLOW_ADD_USER)
                dpm.clearUserRestriction(admin, UserManager.DISALLOW_CONFIG_VPN)
                try {
                    dpm.setAlwaysOnVpnPackage(admin, null, false)
                } catch (_: Exception) {
                }
            }
            return Result.success(Unit)
        }
    }
}
