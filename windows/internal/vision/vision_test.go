package vision

import (
	"encoding/json"
	"image"
	"image/color"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVisionEngineCallsLocalONNXSidecarAndFallsBackGracefully(t *testing.T) {
	// 1. Mock local ONNX ResNet-50 neural sidecar
	var receivedBytes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/analyze":
			data, _ := io.ReadAll(r.Body)
			receivedBytes = len(data)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"safe":   0.09,
				"nsfw":   0.91,
				"engine": "onnx-resnet50-opennsfw",
			})
		}
	}))
	defer srv.Close()

	eng := NewEngine(srv.URL)
	if !eng.CheckNeuralHealth() {
		t.Fatalf("expected neural health check to pass")
	}

	img := image.NewRGBA(image.Rect(0, 0, 400, 300))
	v := eng.AnalyzeRGBA(img)
	if receivedBytes != 224*224*3 {
		t.Fatalf("expected 150528 RGB bytes sent to ONNX sidecar, got %d", receivedBytes)
	}
	if !v.Explicit || v.Confidence < 0.90 || v.Engine != "onnx-resnet50-opennsfw" {
		t.Fatalf("unexpected ONNX verdict: %+v", v)
	}

	// 2. Fallback heuristic when sidecar is offline
	engOffline := NewEngine("http://127.0.0.1:1")
	darkUI := image.NewRGBA(image.Rect(0, 0, 224, 224))
	for y := 0; y < 224; y++ {
		for x := 0; x < 224; x++ {
			darkUI.SetRGBA(x, y, color.RGBA{R: 18, G: 24, B: 38, A: 255})
		}
	}
	vDark := engOffline.AnalyzeRGBA(darkUI)
	if vDark.Explicit {
		t.Fatalf("expected dark UI image to be SAFE, got %+v", vDark)
	}

	// Flat beige wall should also NOT trigger false positive
	flatBeige := image.NewRGBA(image.Rect(0, 0, 224, 224))
	for y := 0; y < 224; y++ {
		for x := 0; x < 224; x++ {
			flatBeige.SetRGBA(x, y, color.RGBA{R: 210, G: 165, B: 135, A: 255})
		}
	}
	vFlat := engOffline.AnalyzeRGBA(flatBeige)
	if vFlat.Explicit {
		t.Fatalf("expected flat beige wall to be rejected by gradient filter, got %+v", vFlat)
	}
}
