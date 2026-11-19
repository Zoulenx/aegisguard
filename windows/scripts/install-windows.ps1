#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Instalador oficial de AegisGuard para Windows (Modo Blindado).
  Instala aegisguard.exe y aegisguard-watchdog.exe como servicios/tareas del sistema (SYSTEM),
  bloquea permisos NTFS, configura DNS local (127.0.0.1) y aplica políticas estrictas en navegadores.
#>

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\AegisGuard"
$DataDir    = "C:\ProgramData\AegisGuard"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistDir    = Join-Path (Split-Path -Parent $ScriptRoot) "dist"

Write-Host "=== Instalando AegisGuard para Windows ===" -ForegroundColor Cyan

# 1. Crear carpetas protegidas
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

# 2. Copiar binarios y extensión
$MainExe     = Join-Path $DistDir "aegisguard.exe"
$WatchdogExe = Join-Path $DistDir "aegisguard-watchdog.exe"
if (!(Test-Path $MainExe) -or !(Test-Path $WatchdogExe)) {
    throw "No se encontraron los ejecutables en $DistDir. Compila primero con build-windows.sh o go build."
}
Copy-Item -Force $MainExe     (Join-Path $InstallDir "aegisguard.exe")
Copy-Item -Force $WatchdogExe (Join-Path $InstallDir "aegisguard-watchdog.exe")
Copy-Item -Recurse -Force (Join-Path (Split-Path -Parent $ScriptRoot) "browser-extension") (Join-Path $InstallDir "browser-extension")

# 3. Aplicar políticas estrictas de navegadores (SafeSearch, sin Incógnito, sin DoH)
& (Join-Path $InstallDir "aegisguard.exe") apply-policies

# 4. Registrar tareas programadas ejecutándose como SYSTEM al iniciar Windows (auto-reinicio en fallo)
$ActionMain = New-ScheduledTaskAction -Execute (Join-Path $InstallDir "aegisguard.exe") -Argument "run --apply-os --data-dir `"$DataDir`""
$TriggerBoot = New-ScheduledTaskTrigger -AtStartup
$PrincipalSys = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)

Register-ScheduledTask -TaskName "AegisGuard-Core" -Action $ActionMain -Trigger $TriggerBoot -Principal $PrincipalSys -Settings $Settings -Force | Out-Null

$ActionWatch = New-ScheduledTaskAction -Execute (Join-Path $InstallDir "aegisguard-watchdog.exe") -Argument "--bin `"$InstallDir\aegisguard.exe`" --apply-os=true"
Register-ScheduledTask -TaskName "AegisGuard-Watchdog" -Action $ActionWatch -Trigger $TriggerBoot -Principal $PrincipalSys -Settings $Settings -Force | Out-Null

# 5. Endurecer permisos NTFS en C:\Program Files\AegisGuard y C:\ProgramData\AegisGuard
# Solo SYSTEM y Administradores conservan control total; usuarios estándar solo lectura/ejecución.
icacls $InstallDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)RX" "BUILTIN\Users:(OI)(CI)RX" | Out-Null
icacls $DataDir    /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)R" | Out-Null

# 6. Iniciar ambos servicios inmediatamente
Start-ScheduledTask -TaskName "AegisGuard-Core"
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName "AegisGuard-Watchdog"

Write-Host ""
Write-Host "[OK] AegisGuard instalado y activo bajo SYSTEM + Watchdog." -ForegroundColor Green
Write-Host "     Panel de control local: http://127.0.0.1:18492" -ForegroundColor Yellow
Write-Host "     Extensión de navegador lista en: $InstallDir\browser-extension" -ForegroundColor Yellow
Write-Host "     (Cargar en Chrome/Edge/Brave en modo desarrollador o mediante política ForceInstall)." -ForegroundColor Gray
