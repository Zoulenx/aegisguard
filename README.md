# AegisGuard v1.1 — Bloqueador Estricto con IA Visual 100% Local (Windows + Android)

**AegisGuard v1.1** bloquea sitios pornográficos, búsquedas sexuales ofuscadas dentro de navegadores y **apps nativas de redes sociales**, pestañas disparadoras (*Reels, Explorar, Shorts, Para ti*), y ahora incluye **IA Visual NSFW 100% local** en **Windows y Android** (analiza en memoria sin guardar capturas ni subir nada a la nube) — **sin monedas, sin puntos y sin atajos de pago**.

---

## Novedades v1.1 — IA Visual 100% Local

### En Windows (`windows/`)
- **`aegisguard-ai.exe`** + **`models/resnet_50_1by2_nsfw.onnx`**: Motor neuronal local **ResNet-50 OpenNSFW** sobre Microsoft ONNX Runtime (`127.0.0.1:18493`, 100% offline).
- **`aegisguard.exe`** (`internal/vision/`): Captura la pantalla activa únicamente en RAM mediante Win32 GDI cada 2.5 segundos, consulta a `aegisguard-ai.exe` (con respaldo heurístico espacial integrado si el motor neuronal no responde), confirma en 2 cuadros consecutivos (o inmediato ≥ 88%) para evitar falsos positivos, minimiza/cierra automáticamente la ventana explícita y registra el bloqueo en la auditoría SHA-256.
- **`aegisguard-watchdog.exe`**: Guardián anti-cierre que reinicia automáticamente el servicio si intentan terminarlo.
- **Un solo instalador** (`scripts/install-windows.ps1`): Instala y registra los 3 servicios bajo `NT AUTHORITY\SYSTEM` (`AegisGuard-VisionAI`, `AegisGuard-Core`, `AegisGuard-Watchdog`).

### En Android (`android/`)
- **`ScreenVisionService.kt`** + **`OnDeviceNsfwScanner.kt`** + **`assets/nsfw.tflite`**: Servicio local con `MediaProjection` + **TensorFlow Lite (OpenNSFW)** embebido dentro del APK.
- Escanea 1 cuadro reducido en RAM cada 2.5s **solo cuando la pantalla está encendida**, nunca guarda imágenes ni envía datos a internet, y lanza automáticamente la pantalla de bloqueo (`BlockOverlayActivity`) al detectar contenido explícito en TikTok, Reels, Telegram, X, Reddit o navegadores (incluso sin palabras clave).

---

## Instalación Rápida (desde Releases v1.1.0)

### 1. Windows (`AegisGuard-Windows-x64-v1.1.zip`)
1. Descomprime el ZIP en tu PC.
2. Abre **PowerShell como Administrador** dentro de esa carpeta y ejecuta:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\scripts\install-windows.ps1
   ```
3. Abre el panel en `http://127.0.0.1:18492` (verás la insignia **IA Visual: ResNet-50 ONNX** y el contador de cuadros/bloqueos).
4. Carga la extensión de navegador de `C:\Program Files\AegisGuard\browser-extension` en Chrome/Edge/Brave.

### 2. Android (`AegisGuard-Android-v1.1.apk`)
1. Instala `AegisGuard-Android-v1.1.apk` en tu móvil.
2. Abre **AegisGuard v1.1** y activa los 3 escudos:
   - **Activar VPN Local** (+ *VPN siempre activa* en Ajustes).
   - **Activar IA Visual en Pantalla (100% Local TFLite)**.
   - **Activar Accesibilidad** (para bloquear búsquedas y *Reels/Explorar/Shorts*).
3. *(Opcional anti-desinstalación sin root)*: Ejecuta `android\scripts\activate-device-owner.bat` por USB y pulsa **Aplicar Blindaje Total Device Owner**.
