# AegisGuard - Protocolo Criptográfico de Desbloqueo y Sincronización (v1)

Este protocolo es compartido de forma idéntica entre **AegisGuard Windows** y **AegisGuard Android** para garantizar que no existan "atajos", monedas, ni pagos de desbloqueo.

## 1. Verificación de Tiempo Real (Anti-Trampa de Reloj)
- Todas las fechas de desbloqueo (`Cooldown`, `Lockdown`, `PanicMode`) se almacenan en segundos Unix UTC.
- Cada verificación consulta servidores NTP (UDP/123: `pool.ntp.org`, `time.cloudflare.com`, `time.google.com`).
- El sistema registra el último timestamp confiable (`last_trusted_utc`) y el tiempo monotónico acumulado.
- Si el reloj local retrocede o salta hacia adelante más de 120 segundos respecto a NTP o respecto al avance monotónico esperado, se marca un **evento de manipulación de reloj (`CLOCK_TAMPER`)** y el desbloqueo queda congelado hasta revalidar con NTP.

## 2. Modos de Protección de Configuración (Combinables)
1. **Temporizador de Enfriamiento (`COOLDOWN`)**:
   - Solicitar un cambio de regla o desbloqueo inicia un conteo regresivo (24h, 72h o 168h / 7 días).
   - El usuario puede **cancelar** la solicitud en cualquier momento con un clic, pero **nunca acelerarla**.
   - Al cumplirse el tiempo verificado por NTP, se abre una ventana de 15 minutos para aplicar el cambio.
2. **Modo Compromiso Estricto (`LOCKDOWN`)**:
   - Bloquea totalmente cualquier cambio de configuración o desinstalación hasta `lockdown_until_utc`.
   - No muestra ni procesa solicitudes de desbloqueo anticipado.
3. **Socio de Responsabilidad (`ACCOUNTABILITY_PARTNER`)**:
   - Al configurarse, se genera una clave secreta de 256 bits (`partner_secret`) que solo conserva una persona de confianza (o un dispositivo separado).
   - Para aprobar un desbloqueo, la app genera un reto de un solo uso `challenge_id` (12 caracteres hex + ventana temporal de 30 minutos).
   - El código de aprobación es:
     `APPROVAL_CODE = UPPER(HEX(HMAC_SHA256(partner_secret, "AEGIS-UNLOCK-V1|" + device_id + "|" + challenge_id))[0:12])`
   - Sin el secreto del socio, es criptográficamente inviable adivinar el código.
4. **Fricción Extrema (`FRICTION_CHALLENGE`)**:
   - Genera una cadena aleatoria de 180 caracteres sin ambigüedades visuales (sin `0/O`, `1/l/I`).
   - El campo de entrada deshabilita pegar (`paste`), autocompletado y arrastre, y exige escribirla manualmente con tasa de error < 2% tras esperar un mínimo de 90 segundos.

## 3. Sincronización Windows ↔ Android (Sin Nube Obligatoria)
- Las reglas y políticas se exportan en un paquete JSON firmado con HMAC-SHA256 (`AegisSyncBundle`), codificado en Base64URL para compartir por código QR o archivo local.
- Regla de convergencia **siempre hacia mayor protección**: al sincronizar, siempre prevalece la fecha de `Lockdown` más lejana y la unión (suma) de palabras/dominios bloqueados.
