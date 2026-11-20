package com.aegisguard.app.vision

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.max
import kotlin.math.min

/**
 * Motor de Visión Artificial NSFW 100% local en dispositivo (TensorFlow Lite + Fallback Heurístico).
 *
 * Privacidad estricta:
 * - Ninguna captura se guarda en disco ni se envía por red.
 * - Soporta automáticamente:
 *   1. OpenNSFW TFLite (`nsfw.tflite`, salida 2 clases [sfw, nsfw], entrada BGR menos media VGG).
 *   2. MobileNetV2 5 clases (`nsfw_mobilenet_v2.tflite`, salida [drawings, hentai, neutral, porn, sexy]).
 *   3. Fallback heurístico espacial YCbCr+HSV en Kotlin puro si no hay modelo .tflite cargado.
 */
class OnDeviceNsfwScanner(
    private val context: Context,
    @Volatile var nsfwThreshold: Float = 0.74f
) {
    private var interpreter: Interpreter? = null
    private var outputClasses: Int = 2
    var engineName: String = "local-heuristic-kotlin"
        private set
    val isNeuralLoaded: Boolean get() = interpreter != null

    data class VisualVerdict(
        val isExplicit: Boolean,
        val confidence: Float,
        val label: String,
        val engine: String
    )

    fun initialize(): Boolean {
        val candidates = listOf("nsfw.tflite", "nsfw_mobilenet_v2.tflite")
        for (fileName in candidates) {
            try {
                val modelBuffer = loadModelFromAssets(fileName) ?: continue
                val opts = Interpreter.Options().apply { numThreads = 2 }
                val interp = Interpreter(modelBuffer, opts)
                val outShape = interp.getOutputTensor(0).shape()
                outputClasses = if (outShape.isNotEmpty()) outShape.last() else 2
                interpreter = interp
                engineName = if (outputClasses == 2) "tflite-opennsfw" else "tflite-mobilenetv2"
                return true
            } catch (_: Exception) {
                // Intenta el siguiente nombre o cae al motor heurístico local
            }
        }
        engineName = "local-heuristic-kotlin"
        return false
    }

    fun analyzeFrameInMemory(frame: Bitmap): VisualVerdict {
        val tflite = interpreter
        if (tflite != null) {
            return runTfliteInference(tflite, frame)
        }
        val score = analyzeHeuristic(frame)
        return VisualVerdict(
            isExplicit = score >= nsfwThreshold,
            confidence = score,
            label = if (score >= nsfwThreshold) "nsfw_heuristic" else "safe",
            engine = engineName
        )
    }

    private fun runTfliteInference(tflite: Interpreter, frame: Bitmap): VisualVerdict {
        return if (outputClasses == 2) {
            // Preprocesamiento exacto de Yahoo OpenNSFW (256x256 -> center crop 224x224, BGR - VGG_MEAN)
            val scaled256 = Bitmap.createScaledBitmap(frame, 256, 256, true)
            val inputBuffer = bitmapToOpenNsfwBgrBuffer(scaled256)
            if (scaled256 != frame) scaled256.recycle()

            val output = Array(1) { FloatArray(2) }
            tflite.run(inputBuffer, output)
            val nsfwScore = output[0][1].coerceIn(0f, 1f)
            VisualVerdict(
                isExplicit = nsfwScore >= nsfwThreshold,
                confidence = nsfwScore,
                label = if (nsfwScore >= nsfwThreshold) "nsfw" else "safe",
                engine = engineName
            )
        } else {
            // MobileNetV2 5 clases: [drawings, hentai, neutral, porn, sexy] o 4 clases [neutral, sexy, porn, hentai]
            val scaled224 = Bitmap.createScaledBitmap(frame, INPUT_SIZE, INPUT_SIZE, true)
            val inputBuffer = bitmapToNormalizedRgbBuffer(scaled224)
            if (scaled224 != frame) scaled224.recycle()

            val output = Array(1) { FloatArray(outputClasses) }
            tflite.run(inputBuffer, output)
            val scores = output[0]
            val explicitScore = when (outputClasses) {
                5 -> max(scores[1], scores[3]) // max(hentai, porn)
                4 -> max(scores[2], scores[3]) // max(porn, hentai)
                else -> scores.lastOrNull() ?: 0f
            }.coerceIn(0f, 1f)
            VisualVerdict(
                isExplicit = explicitScore >= nsfwThreshold,
                confidence = explicitScore,
                label = if (explicitScore >= nsfwThreshold) "explicit" else "safe",
                engine = engineName
            )
        }
    }

    private fun bitmapToOpenNsfwBgrBuffer(bmp256: Bitmap): ByteBuffer {
        val buf = ByteBuffer.allocateDirect(4 * INPUT_SIZE * INPUT_SIZE * 3)
        buf.order(ByteOrder.LITTLE_ENDIAN)
        val pixels = IntArray(INPUT_SIZE * INPUT_SIZE)
        val startX = max((bmp256.width - INPUT_SIZE) / 2, 0)
        val startY = max((bmp256.height - INPUT_SIZE) / 2, 0)
        bmp256.getPixels(pixels, 0, INPUT_SIZE, startX, startY, INPUT_SIZE, INPUT_SIZE)
        for (c in pixels) {
            buf.putFloat(Color.blue(c) - VGG_MEAN_B)
            buf.putFloat(Color.green(c) - VGG_MEAN_G)
            buf.putFloat(Color.red(c) - VGG_MEAN_R)
        }
        buf.rewind()
        return buf
    }

    private fun bitmapToNormalizedRgbBuffer(bmp224: Bitmap): ByteBuffer {
        val buf = ByteBuffer.allocateDirect(4 * INPUT_SIZE * INPUT_SIZE * 3)
        buf.order(ByteOrder.nativeOrder())
        val pixels = IntArray(INPUT_SIZE * INPUT_SIZE)
        bmp224.getPixels(pixels, 0, INPUT_SIZE, 0, 0, INPUT_SIZE, INPUT_SIZE)
        for (c in pixels) {
            buf.putFloat(Color.red(c) / 255.0f)
            buf.putFloat(Color.green(c) / 255.0f)
            buf.putFloat(Color.blue(c) / 255.0f)
        }
        buf.rewind()
        return buf
    }

    private fun analyzeHeuristic(frame: Bitmap): Float {
        val scaled = Bitmap.createScaledBitmap(frame, INPUT_SIZE, INPUT_SIZE, true)
        val pixels = IntArray(INPUT_SIZE * INPUT_SIZE)
        scaled.getPixels(pixels, 0, INPUT_SIZE, 0, 0, INPUT_SIZE, INPUT_SIZE)
        if (scaled != frame) scaled.recycle()

        var skinTotal = 0.0
        var centerSkin = 0.0
        var centerTotal = 0.0
        var gradSum = 0.0
        var transitions = 0.0

        for (y in 0 until INPUT_SIZE) {
            val inCenterY = y in 32 until 192
            var prevLum = 0.0
            for (x in 0 until INPUT_SIZE) {
                val inCenter = inCenterY && x in 32 until 192
                if (inCenter) centerTotal++
                val c = pixels[y * INPUT_SIZE + x]
                val r = Color.red(c).toDouble()
                val g = Color.green(c).toDouble()
                val b = Color.blue(c).toDouble()

                val yVal = 0.299 * r + 0.587 * g + 0.114 * b
                val cb = 128.0 - 0.168736 * r - 0.331264 * g + 0.5 * b
                val cr = 128.0 + 0.5 * r - 0.418688 * g - 0.081312 * b

                val isSkin = yVal > 45 && cb in 77.0..127.0 && cr in 133.0..173.0 &&
                    r > 80 && g > 40 && b > 20 && r > g && r > b && abs(r - g) > 12
                if (isSkin) {
                    skinTotal++
                    if (inCenter) centerSkin++
                    if (x > 0) {
                        val diff = abs(yVal - prevLum)
                        gradSum += diff
                        if (diff in 2.5..35.0) transitions++
                    }
                }
                prevLum = yVal
            }
        }
        if (skinTotal < 1500.0) return 0.05f
        val meanGrad = gradSum / skinTotal
        if (meanGrad < 1.2) return 0.10f

        val globalRatio = skinTotal / (INPUT_SIZE * INPUT_SIZE).toDouble()
        val centerRatio = centerSkin / max(centerTotal, 1.0)
        val texture = min((transitions / skinTotal) * 2.0, 1.0)
        val z = -4.6 + 5.2 * centerRatio + 2.8 * globalRatio + 1.4 * texture
        return (1.0 / (1.0 + exp(-z))).toFloat().coerceIn(0f, 1f)
    }

    fun close() {
        interpreter?.close()
        interpreter = null
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
        private const val VGG_MEAN_B = 103.939f
        private const val VGG_MEAN_G = 116.779f
        private const val VGG_MEAN_R = 123.68f
    }
}
