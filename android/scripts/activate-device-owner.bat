@echo off
REM Activa AegisGuard como Propietario del Dispositivo (Device Owner) via USB/ADB (SIN ROOT).
REM Requisito oficial de Android: elimina temporalmente cuentas de Google del telefono antes de ejecutarlo,
REM y vuelve a iniciar sesion justo despues de ver "Success".

echo === Activando AegisGuard Device Owner (Anti-Desinstalacion Nivel Sistema) ===
adb devices
adb shell dpm set-device-owner com.aegisguard.app/.admin.AegisDeviceAdminReceiver
echo.
echo [OK] Si aparecio "Success", abre AegisGuard en tu movil y pulsa "Aplicar Blindaje Total Device Owner".
pause
