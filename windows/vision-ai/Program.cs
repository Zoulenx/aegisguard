using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

// AegisGuard Vision AI Sidecar (v1.1) — 100% Local ONNX Runtime ResNet-50 OpenNSFW
// Escucha SOLO en 127.0.0.1:18493. Nunca guarda capturas en disco ni envía datos a internet.

const int InputSize = 224;
const int ExpectedRgbBytes = InputSize * InputSize * 3;
const string ListenPrefix = "http://127.0.0.1:18493/";

string exeDir = AppContext.BaseDirectory;
string modelPath = args.Length > 0
    ? args[0]
    : Path.Combine(exeDir, "models", "resnet_50_1by2_nsfw.onnx");

if (!File.Exists(modelPath))
{
    Console.Error.WriteLine($"[AegisVisionAI] ERROR: Modelo ONNX no encontrado en: {modelPath}");
    return 1;
}

var sessionOpts = new SessionOptions
{
    IntraOpNumThreads = Math.Clamp(Environment.ProcessorCount / 2, 1, 4),
    GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL
};

using var session = new InferenceSession(modelPath, sessionOpts);
string inputName = session.InputMetadata.Keys.First();
Console.WriteLine($"[AegisVisionAI] Modelo ResNet-50 OpenNSFW cargado ({modelPath}). Input: {inputName}");

using var listener = new HttpListener();
listener.Prefixes.Add(ListenPrefix);
listener.Start();
Console.WriteLine($"[AegisVisionAI] Escuchando solo en local: {ListenPrefix}");

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); listener.Stop(); };

while (!cts.IsCancellationRequested)
{
    HttpListenerContext ctx;
    try
    {
        ctx = await listener.GetContextAsync();
    }
    catch
    {
        break;
    }

    _ = Task.Run(async () =>
    {
        try
        {
            string path = ctx.Request.Url?.AbsolutePath ?? "/";
            if (path == "/health")
            {
                await WriteJsonAsync(ctx.Response, 200, new { status = "ok", engine = "onnx-resnet50-opennsfw" });
                return;
            }

            if (path == "/analyze" && ctx.Request.HttpMethod == "POST")
            {
                using var ms = new MemoryStream(ExpectedRgbBytes);
                await ctx.Request.InputStream.CopyToAsync(ms);
                byte[] rgb = ms.ToArray();
                if (rgb.Length != ExpectedRgbBytes)
                {
                    await WriteJsonAsync(ctx.Response, 400, new { error = $"Expected {ExpectedRgbBytes} raw RGB bytes, got {rgb.Length}" });
                    return;
                }

                // Yahoo OpenNSFW ResNet-50 espera NCHW [1, 3, 224, 224] en orden BGR menos [104, 117, 123]
                float[] tensorData = new float[ExpectedRgbBytes];
                const int planeSize = InputSize * InputSize;
                for (int i = 0; i < planeSize; i++)
                {
                    int rgbIdx = i * 3;
                    byte r = rgb[rgbIdx];
                    byte g = rgb[rgbIdx + 1];
                    byte b = rgb[rgbIdx + 2];

                    tensorData[i] = b - 104.0f;                  // Canal 0: B
                    tensorData[planeSize + i] = g - 117.0f;      // Canal 1: G
                    tensorData[2 * planeSize + i] = r - 123.0f;  // Canal 2: R
                }

                var inputTensor = new DenseTensor<float>(tensorData, new[] { 1, 3, InputSize, InputSize });
                var inputs = new List<NamedOnnxValue> { NamedOnnxValue.CreateFromTensor(inputName, inputTensor) };

                float safeScore = 1.0f;
                float nsfwScore = 0.0f;
                lock (session)
                {
                    using var results = session.Run(inputs);
                    var output = results.Last().AsTensor<float>().ToArray();
                    if (output.Length >= 2)
                    {
                        safeScore = output[0];
                        nsfwScore = output[1];
                    }
                }

                await WriteJsonAsync(ctx.Response, 200, new
                {
                    safe = safeScore,
                    nsfw = nsfwScore,
                    engine = "onnx-resnet50-opennsfw"
                });
                return;
            }

            await WriteJsonAsync(ctx.Response, 404, new { error = "not found" });
        }
        catch (Exception ex)
        {
            try
            {
                await WriteJsonAsync(ctx.Response, 500, new { error = ex.Message });
            }
            catch { }
        }
    });
}

return 0;

static async Task WriteJsonAsync(HttpListenerResponse resp, int statusCode, object payload)
{
    resp.StatusCode = statusCode;
    resp.ContentType = "application/json; charset=utf-8";
    byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
    resp.ContentLength64 = bytes.Length;
    await resp.OutputStream.WriteAsync(bytes);
    resp.Close();
}
