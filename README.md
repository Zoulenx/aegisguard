# AegisGuard — Bloqueador Estricto de Contenido Explícito (Windows + Android)

**AegisGuard** es un sistema multiplataforma diseñado para bloquear sitios pornográficos, búsquedas sexuales ofuscadas dentro de navegadores y **apps nativas de redes sociales**, y pestañas disparadoras (*Reels, Explorar, Shorts, Para ti*) — **sin monedas, sin puntos y sin atajos de pago para desbloquearlo**.

---

## Estructura del Proyecto

- `shared/` — Reglas compartidas (dominios adultos + servidores DoH de evasión + proxies, diccionario semántico ES/EN anti-ofuscación, firmas de redes sociales y especificación del protocolo criptográfico).
- `windows/` — Aplicación nativa para Windows en Go + extensión de navegador Manifest V3 + instalador blindado PowerShell.
  - **`windows/dist/aegisguard.exe`** (binario x64 ya compilado)
  - **`windows/dist/aegisguard-watchdog.exe`** (guardián anti-cierre x64 ya compilado)
  - `windows/browser-extension/` (Chrome / Edge / Brave)
  - `windows/scripts/install-windows.ps1` (instalador bajo `NT AUTHORITY\SYSTEM`)
- `android/` — Proyecto nativo completo en Kotlin + Jetpack Compose + Gradle (`com.aegisguard.app`).
  - `AegisVpnService.kt`: VPN local Always-On para bloqueo DNS web/apps + Cloudflare Family `1.1.1.3`.
  - `ContentGuardAccessibilityService.kt`: Filtrado en tiempo real dentro de Instagram, TikTok, X, Reddit, Telegram, YouTube, Facebook y navegadores + bloqueo de pestañas disparadoras + escudo anti-manipulación de Ajustes.
  - `AegisDeviceAdminReceiver.kt`: Soporte completo **Device Owner** (impide desinstalar, impide Modo Seguro, impide cambiar fecha/hora y bloquea la VPN como obligatoria).
  - `OnDeviceNsfwScanner.kt`: Motor opcional de visión artificial NSFW 100% local con TensorFlow Lite (sin subir nada a la nube).

---

## Instalación en Windows (PC)

Los ejecutables `windows/dist/aegisguard.exe` y `windows/dist/aegisguard-watchdog.exe` ya están compilados para Windows 64-bit.

1. Copia la carpeta `windows/` a tu PC con Windows.
2. Abre **PowerShell como Administrador** y ejecuta:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\scripts\install-windows.ps1
   ```
3. Esto instala ambos ejecutables en `C:\Program Files\AegisGuard`, bloquea permisos NTFS, aplica políticas de navegadores (SafeSearch forzado, sin Incógnito, sin DoH de evasión), configura DNS local (`127.0.0.1`) y registra las tareas bajo `SYSTEM` con auto-reinicio.
4. Abre el panel de control en tu navegador: **`http://127.0.0.1:18492`**.
5. Carga la extensión de navegador ubicada en `C:\Program Files\AegisGuard\browser-extension` en Chrome/Edge/Brave.

### Generar código de aprobación (Persona de Confianza)
Tu persona de confianza puede generar el código HMAC de un solo uso sin conexión a internet:
```powershell
aegisguard.exe partner-approve --secret <CLAVE_SECRETA> --device <DEVICE_ID> --challenge <RETO_ID>
```

---

## Compilación e Instalación en Android (Móvil)

1. Abre la carpeta `android/` en **Android Studio** (o compila con Gradle si tienes el Android SDK instalado):
   ```bash
   ./gradlew assembleRelease
   ```
2. Instala el APK en tu teléfono Android.
3. **(Recomendado para blindaje máximo anti-desinstalación, sin root)**:
   - Activa Depuración USB en tu teléfono, retira temporalmente las cuentas de Google en Ajustes → Cuentas, conecta el cable USB a tu PC y ejecuta:
     - En Windows: `android\scripts\activate-device-owner.bat`
     - En Linux/macOS: `bash android/scripts/activate-device-owner.sh`
   - Vuelve a añadir tu cuenta de Google.
4. Abre **AegisGuard** en el teléfono y activa:
   - **VPN Local** (y marca *VPN siempre activa* + *Bloquear conexiones sin VPN*).
   - **Servicio de Accesibilidad** (para filtrar búsquedas dentro de Instagram, TikTok, X, Telegram, Reddit, etc.).
   - **Aplicar Blindaje Total Device Owner**.
5. *(Opcional IA Visual)*: Para activar la detección visual NSFW local sin nube, coloca el modelo cuantizado `nsfw_mobilenet_v2.tflite` en `android/app/src/main/assets/` antes de compilar.
