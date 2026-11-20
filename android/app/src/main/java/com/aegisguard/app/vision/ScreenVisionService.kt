package com.aegisguard.app.vision

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.PowerManager
import com.aegisguard.app.security.LockManager
import com.aegisguard.app.ui.BlockOverlayActivity
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Servicio de Escaneo Visual IA 100% Local (MediaProjection + TensorFlow Lite).
 * - Captura 1 cuadro reducido (320x480) en RAM cada 2.5 segundos SOLO cuando la pantalla está encendida.
 * - Nunca guarda imágenes en almacenamiento ni las envía por red.
 * - Requiere 2 cuadros consecutivos explícitos (o 1 cuadro >= 88%) para evitar falsos positivos.
 * - Al detectar contenido explícito (incluso en TikTok, Reels, Telegram, X sin palabras clave),
 *   lanza BlockOverlayActivity inmediatamente.
 */
class ScreenVisionService : Service() {

    private var mediaProjection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var workerThread: HandlerThread? = null
    private var workerHandler: Handler? = null

    private lateinit var scanner: OnDeviceNsfwScanner
    private lateinit var lockManager: LockManager
    private lateinit var powerManager: PowerManager

    private var consecutiveHits = 0
    private var lastBlockMs = 0L

    private val scanRunnable = object : Runnable {
        override fun run() {
            if (!isRunning.get()) return
            try {
                if (powerManager.isInteractive) {
                    inspectLatestFrame()
                }
            } catch (_: Exception) {
            }
            workerHandler?.postDelayed(this, SCAN_INTERVAL_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        lockManager = LockManager.getInstance(this)
        powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        scanner = OnDeviceNsfwScanner(this, nsfwThreshold = activeThreshold)
        scanner.initialize()
        activeEngineName = scanner.engineName
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            val (locked, _) = lockManager.isSettingsLocked()
            if (!locked) {
                stopCapture()
                stopSelf()
                return START_NOT_STICKY
            }
            return START_STICKY
        }

        startForeground(NOTIF_ID, buildNotification())

        val resultCode = intent?.getIntExtra(EXTRA_RESULT_CODE, Activity.RESULT_CANCELED) ?: Activity.RESULT_CANCELED
        val data: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent?.getParcelableExtra(EXTRA_RESULT_DATA, Intent::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent?.getParcelableExtra(EXTRA_RESULT_DATA)
        }

        if (resultCode != Activity.RESULT_OK || data == null) {
            stopSelf()
            return START_NOT_STICKY
        }

        startCapture(resultCode, data)
        return START_STICKY
    }

    private fun startCapture(resultCode: Int, data: Intent) {
        stopCapture()
        val mgr = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val projection = mgr.getMediaProjection(resultCode, data) ?: return
        mediaProjection = projection

        val thread = HandlerThread("AegisGuard-VisionAI").apply { start() }
        val handler = Handler(thread.looper)
        workerThread = thread
        workerHandler = handler

        projection.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() {
                stopCapture()
                stopSelf()
            }
        }, handler)

        val reader = ImageReader.newInstance(CAPTURE_W, CAPTURE_H, PixelFormat.RGBA_8888, 2)
        imageReader = reader
        virtualDisplay = projection.createVirtualDisplay(
            "AegisGuardVision",
            CAPTURE_W,
            CAPTURE_H,
            160,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            reader.surface,
            null,
            handler
        )

        isRunning.set(true)
        handler.postDelayed(scanRunnable, 1500L)
        lockManager.appendAudit("VISION_AI_STARTED", "IA Visual 100% local activa (${scanner.engineName})")
    }

    private fun inspectLatestFrame() {
        scanner.nsfwThreshold = activeThreshold
        val reader = imageReader ?: return
        val image = reader.acquireLatestImage() ?: return
        var bitmap: Bitmap? = null
        try {
            val plane = image.planes[0]
            val buffer = plane.buffer
            val pixelStride = plane.pixelStride
            val rowStride = plane.rowStride
            val rowPadding = rowStride - pixelStride * CAPTURE_W

            val padded = Bitmap.createBitmap(
                CAPTURE_W + rowPadding / pixelStride,
                CAPTURE_H,
                Bitmap.Config.ARGB_8888
            )
            padded.copyPixelsFromBuffer(buffer)
            bitmap = Bitmap.createBitmap(padded, 0, 0, CAPTURE_W, CAPTURE_H)
            if (padded != bitmap) padded.recycle()

            framesScannedCount.incrementAndGet()
            val verdict = scanner.analyzeFrameInMemory(bitmap)
            lastConfidencePct = (verdict.confidence * 100).toInt()

            if (verdict.isExplicit) {
                consecutiveHits++
            } else {
                consecutiveHits = 0
            }

            val instantBlock = verdict.confidence >= 0.88f
            val now = System.currentTimeMillis()
            if (verdict.isExplicit && (instantBlock || consecutiveHits >= 2) && (now - lastBlockMs > 4000L)) {
                lastBlockMs = now
                consecutiveHits = 0
                visualBlocksCount.incrementAndGet()

                val pct = (verdict.confidence * 100).toInt()
                val msg = "IA Visual (${verdict.engine}) detectó contenido explícito en pantalla ($pct%)"
                lockManager.appendAudit("VISUAL_NSFW_BLOCK", msg)

                val overlay = Intent(this, BlockOverlayActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    putExtra(BlockOverlayActivity.EXTRA_SOURCE_APP, "IA Visual en Pantalla")
                    putExtra(BlockOverlayActivity.EXTRA_REASON, msg)
                }
                startActivity(overlay)
            }
        } finally {
            bitmap?.recycle()
            image.close()
        }
    }

    private fun buildNotification(): Notification {
        val channelId = "aegisguard_vision_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                channelId,
                "IA Visual Local AegisGuard",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("AegisGuard IA Visual Activa")
            .setContentText("Analizando pantalla 100% local (${scanner.engineName}) — cero nube")
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setOngoing(true)
            .build()
    }

    private fun stopCapture() {
        isRunning.set(false)
        workerHandler?.removeCallbacks(scanRunnable)
        virtualDisplay?.release()
        virtualDisplay = null
        imageReader?.close()
        imageReader = null
        mediaProjection?.stop()
        mediaProjection = null
        workerThread?.quitSafely()
        workerThread = null
        workerHandler = null
    }

    override fun onDestroy() {
        stopCapture()
        scanner.close()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val ACTION_STOP = "com.aegisguard.app.STOP_VISION_AI"
        const val EXTRA_RESULT_CODE = "extra_result_code"
        const val EXTRA_RESULT_DATA = "extra_result_data"

        private const val NOTIF_ID = 1002
        private const val CAPTURE_W = 320
        private const val CAPTURE_H = 480
        private const val SCAN_INTERVAL_MS = 2500L

        val isRunning = AtomicBoolean(false)
        val framesScannedCount = AtomicLong(0)
        val visualBlocksCount = AtomicLong(0)
        @Volatile var activeEngineName: String = "tflite-opennsfw"
        @Volatile var activeThreshold: Float = 0.74f
        @Volatile var lastConfidencePct: Int = 0
    }
}
