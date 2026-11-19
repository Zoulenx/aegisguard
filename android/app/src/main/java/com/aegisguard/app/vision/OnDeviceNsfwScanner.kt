package com.aegisguard.app.vision

import android.content.Context
import android.graphics.Bitmap
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel

/**
 * Motor de Visión Artificial NSFW 100% local en dispositivo (TensorFlow Lite).
 *
 * Privacidad estricta:
 * - Ninguna captura de pantalla se guarda en disco ni se envía a internet.
 * - Solo se ejecuta en memoria RAM sobre cuadros reducidos (224x224) cuando la app en primer plano
 *   es una red social configurada (Instagram, TikTok, X, Telegram, Reddit) para proteger la batería.
 *
 * Para activar el modelo visual completo, coloca un modelo cuantizado `nsfw_mobilenet_v2.tflite`
 * (entrada 224x224 RGB float32, salida [safe, sexy, porn, hentai]) en `app/src/main/assets/`.
 */
class OnDeviceNsfwScanner(
    private val context: Context,
    private val nsfwThreshold: Float = 0.72f
) {
    private var interpreter: Interpreter? = null

    fun initialize(): Boolean {
        return try {
            val modelBuffer = loadModelFromAssets("nsfw_mobilenet_v2.tflite") ?: return false
            val opts = Interpreter.Options().apply { numThreads = 2 }
            interpreter = Interpreter(modelBuffer, opts)
            true
        } catch (_: Exception) {
            false
        }
    }

    data class VisualVerdict(
        val isExplicit: Boolean,
        val confidence: Float,
        val label: String
    )

    fun analyzeFrameInMemory(frame: Bitmap): VisualVerdict {
        val tflite = interpreter ?: return VisualVerdict(false, 0f, "model_not_loaded")
        val scaled = Bitmap.createScaledBitmap(frame, INPUT_SIZE, INPUT_SIZE, true)
        val inputBuffer = bitmapToFloatBuffer(scaled)
        if (scaled != frame) scaled.recycle()

        // Salida estándar de 4 clases: [neutral, sexy/suggestive, porn, hentai]
        val output = Array(1) { FloatArray(4) }
        tflite.run(inputBuffer, output)

        val scores = output[0]
        val pornScore = scores[2]
        val hentaiScore = scores[3]
        val combinedExplicit = maxOf(pornScore, hentaiScore)
        val label = if (pornScore >= hentaiScore) "porn" else "hentai"

        return VisualVerdict(
            isExplicit = combinedExplicit >= nsfwThreshold,
            confidence = combinedExplicit,
            label = label
        )
    }

    fun close() {
        interpreter?.close()
        interpreter = null
    }

    private fun bitmapToFloatBuffer(bmp: Bitmap): ByteBuffer {
        val buf = ByteBuffer.allocateDirect(4 * INPUT_SIZE * INPUT_SIZE * 3)
        buf.order(ByteOrder.nativeOrder())
        val pixels = IntArray(INPUT_SIZE * INPUT_SIZE)
        bmp.getPixels(pixels, 0, INPUT_SIZE, 0, 0, INPUT_SIZE, INPUT_SIZE)
        for (px in pixels) {
            buf.putFloat(((px shr 16) and 0xFF) / 255.0f)
            buf.putFloat(((px shr 8) and 0xFF) / 255.0f)
            buf.putFloat((px and 0xFF) / 255.0f)
        }
        buf.rewind()
        return buf
    }

    private fun loadModelFromAssets(fileName: String): MappedByteBuffer? {
        return try {
            val afd = context.assets.openFd(fileName)
            FileInputStream(afd.fileDescriptor).use { fis ->
                fis.channel.map(FileChannel.MapMode.READ_ONLY, afd.startOffset, afd.declaredLength)
            }
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        private const val INPUT_SIZE = 224
    }
}
