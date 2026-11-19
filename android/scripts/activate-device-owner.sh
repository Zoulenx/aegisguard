#!/usr/bin/env bash
# Activa AegisGuard como Propietario del Dispositivo (Device Owner) vía USB/ADB (SIN ROOT).
# Requisito de Android: elimina temporalmente cuentas de Google/trabajo del teléfono antes de ejecutar este comando,
# y vuelve a añadirlas inmediatamente después de que salga "Success".

set -euo pipefail

echo "=== Activando AegisGuard Device Owner (Anti-Desinstalación Nivel Sistema) ==="
adb devices
adb shell dpm set-device-owner com.aegisguard.app/.admin.AegisDeviceAdminReceiver
echo ""
echo "[OK] AegisGuard ahora es Device Owner."
echo "Abre la app AegisGuard en tu teléfono y pulsa 'Aplicar Blindaje Total Device Owner'."
