package vision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Verdict struct {
	Explicit   bool    `json:"explicit"`
	Confidence float64 `json:"confidence"`
	Engine     string  `json:"engine"`
	Reason     string  `json:"reason,omitempty"`
}

type Stats struct {
	Enabled         bool    `json:"enabled"`
	Engine          string  `json:"engine"`
	NeuralConnected bool    `json:"neural_connected"`
	FramesScanned   uint64  `json:"frames_scanned"`
	VisualBlocks    uint64  `json:"visual_blocks"`
	LastConfidence  float64 `json:"last_confidence"`
	Threshold       float64 `json:"threshold"`
}

type Engine struct {
	mu               sync.RWMutex
	aiEndpoint       string
	httpClient       *http.Client
	threshold        float64
	instantThreshold float64
	enabled          atomic.Bool
	neuralConnected  atomic.Bool
	framesScanned    atomic.Uint64
	visualBlocks     atomic.Uint64
	lastConfidence   atomic.Uint64 // float64 bits
	consecutiveHits  int
}

func NewEngine(aiEndpoint string) *Engine {
	if aiEndpoint == "" {
		aiEndpoint = "http://127.0.0.1:18493"
	}
	e := &Engine{
		aiEndpoint:       aiEndpoint,
		httpClient:       &http.Client{Timeout: 1500 * time.Millisecond},
		threshold:        0.74,
		instantThreshold: 0.88,
	}
	e.enabled.Store(true)
	return e
}

func (e *Engine) SetThreshold(t float64) {
	if t < 0.50 {
		t = 0.50
	}
	if t > 0.95 {
		t = 0.95
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threshold = t
}

func (e *Engine) Stats() Stats {
	e.mu.RLock()
	thr := e.threshold
	e.mu.RUnlock()
	eng := "local-heuristic-go"
	if e.neuralConnected.Load() {
		eng = "onnx-resnet50-opennsfw"
	}
	return Stats{
		Enabled:         e.enabled.Load(),
		Engine:          eng,
		NeuralConnected: e.neuralConnected.Load(),
		FramesScanned:   e.framesScanned.Load(),
		VisualBlocks:    e.visualBlocks.Load(),
		LastConfidence:  math.Float64frombits(e.lastConfidence.Load()),
		Threshold:       thr,
	}
}

// CheckNeuralHealth pings the local ONNX ResNet-50 sidecar (127.0.0.1:18493/health).
func (e *Engine) CheckNeuralHealth() bool {
	resp, err := e.httpClient.Get(e.aiEndpoint + "/health")
	if err != nil {
		e.neuralConnected.Store(false)
		return false
	}
	_ = resp.Body.Close()
	ok := resp.StatusCode == http.StatusOK
	e.neuralConnected.Store(ok)
	return ok
}

// AnalyzeRGBA evaluates an in-memory screenshot (never written to disk, never sent to internet).
// Prefers local ONNX ResNet-50 neural engine and falls back to built-in pure-Go visual analyzer.
func (e *Engine) AnalyzeRGBA(img *image.RGBA) Verdict {
	if img == nil || img.Bounds().Empty() {
		return Verdict{Engine: "none"}
	}
	e.framesScanned.Add(1)

	rgb224 := ResizeTo224RGB(img)
	e.mu.RLock()
	thr := e.threshold
	e.mu.RUnlock()

	// Tier 1: Local ONNX ResNet-50 Neural Network (127.0.0.1:18493)
	if nsfwScore, engineName, err := e.queryLocalONNX(rgb224); err == nil {
		e.neuralConnected.Store(true)
		e.lastConfidence.Store(math.Float64bits(nsfwScore))
		explicit := nsfwScore >= thr
		reason := ""
		if explicit {
			reason = fmt.Sprintf("IA Visual (%s) detectó contenido explícito (%.0f%%)", engineName, nsfwScore*100)
		}
		return Verdict{
			Explicit:   explicit,
			Confidence: nsfwScore,
			Engine:     engineName,
			Reason:     reason,
		}
	}

	// Tier 2: Built-in pure-Go multi-zone YCbCr+HSV skin-exposure & texture entropy analyzer
	e.neuralConnected.Store(false)
	score := AnalyzeHeuristicRGB224(rgb224)
	e.lastConfidence.Store(math.Float64bits(score))
	explicit := score >= thr
	reason := ""
	if explicit {
		reason = fmt.Sprintf("IA Visual local (heurística espacial) detectó exposición explícita (%.0f%%)", score*100)
	}
	return Verdict{
		Explicit:   explicit,
		Confidence: score,
		Engine:     "local-heuristic-go",
		Reason:     reason,
	}
}

// StartGuard runs periodic in-memory screen scanning on Windows with temporal anti-false-positive smoothing.
func (e *Engine) StartGuard(ctx context.Context, interval time.Duration, onBlock func(windowTitle string, v Verdict)) {
	if interval <= 0 {
		interval = 2500 * time.Millisecond
	}
	go func() {
		e.CheckNeuralHealth()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !e.enabled.Load() {
					continue
				}
				frame, title, err := CaptureActiveScreen()
				if err != nil || frame == nil {
					continue
				}
				verdict := e.AnalyzeRGBA(frame)
				e.mu.Lock()
				if verdict.Explicit {
					e.consecutiveHits++
				} else {
					e.consecutiveHits = 0
				}
				hits := e.consecutiveHits
				instant := verdict.Confidence >= e.instantThreshold
				e.mu.Unlock()

				// Require either very high single-frame confidence (>=88%) or 2 consecutive frames
				if verdict.Explicit && (instant || hits >= 2) {
					e.visualBlocks.Add(1)
					e.mu.Lock()
					e.consecutiveHits = 0
					e.mu.Unlock()
					InterveneOnVisualBlock()
					if onBlock != nil {
						onBlock(title, verdict)
					}
				}
			}
		}
	}()
}

func (e *Engine) queryLocalONNX(rgb224 []byte) (float64, string, error) {
	req, err := http.NewRequest(http.MethodPost, e.aiEndpoint+"/analyze", bytes.NewReader(rgb224))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("onnx status %d", resp.StatusCode)
	}
	var out struct {
		NSFW   float64 `json:"nsfw"`
		Safe   float64 `json:"safe"`
		Engine string  `json:"engine"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, "", err
	}
	if out.Engine == "" {
		out.Engine = "onnx-resnet50-opennsfw"
	}
	return out.NSFW, out.Engine, nil
}

// ResizeTo224RGB converts any RGBA image into a 224x224x3 raw RGB byte slice (150,528 bytes)
// using fast bilinear-like area sampling in memory.
func ResizeTo224RGB(src *image.RGBA) []byte {
	const dstSize = 224
	b := src.Bounds()
	srcW := b.Dx()
	srcH := b.Dy()
	out := make([]byte, dstSize*dstSize*3)
	if srcW <= 0 || srcH <= 0 {
		return out
	}

	idx := 0
	for y := 0; y < dstSize; y++ {
		sy := b.Min.Y + (y*srcH)/dstSize
		rowOff := (sy - src.Rect.Min.Y) * src.Stride
		for x := 0; x < dstSize; x++ {
			sx := b.Min.X + (x*srcW)/dstSize
			p := rowOff + (sx-src.Rect.Min.X)*4
			out[idx] = src.Pix[p]     // R
			out[idx+1] = src.Pix[p+1] // G
			out[idx+2] = src.Pix[p+2] // B
			idx += 3
		}
	}
	return out
}

// AnalyzeHeuristicRGB224 computes a conservative local NSFW visual risk score [0.0..1.0]
// combining YCbCr + HSV skin modeling, center-frame concentration, and gradient variance
// (rejecting flat solid tan/beige/wooden backgrounds or dark UI screens).
func AnalyzeHeuristicRGB224(rgb []byte) float64 {
	const size = 224
	if len(rgb) < size*size*3 {
		return 0
	}

	totalPixels := float64(size * size)
	centerTotal := 0.0
	skinTotal := 0.0
	centerSkin := 0.0
	skinGradientSum := 0.0
	skinTransitions := 0.0

	isSkinAt := func(x, y int) (bool, float64) {
		p := (y*size + x) * 3
		r := float64(rgb[p])
		g := float64(rgb[p+1])
		b := float64(rgb[p+2])

		// YCbCr skin chromaticity cluster (Chai & Ngan + Kovac refined thresholds)
		yVal := 0.299*r + 0.587*g + 0.114*b
		cb := 128.0 - 0.168736*r - 0.331264*g + 0.5*b
		cr := 128.0 + 0.5*r - 0.418688*g - 0.081312*b

		ycbcrSkin := yVal > 45 && cb >= 77 && cb <= 127 && cr >= 133 && cr <= 173
		rgbSkin := r > 80 && g > 40 && b > 20 && r > g && r > b && math.Abs(r-g) > 12
		return ycbcrSkin && rgbSkin, yVal
	}

	for y := 0; y < size; y++ {
		inCenterY := y >= 32 && y < 192
		var prevY float64
		for x := 0; x < size; x++ {
			inCenter := inCenterY && x >= 32 && x < 192
			if inCenter {
				centerTotal++
			}
			skin, lum := isSkinAt(x, y)
			if skin {
				skinTotal++
				if inCenter {
					centerSkin++
				}
				if x > 0 {
					diff := math.Abs(lum - prevY)
					skinGradientSum += diff
					if diff > 2.5 && diff < 35.0 {
						skinTransitions++
					}
				}
			}
			prevY = lum
		}
	}

	if skinTotal < 1500 {
		return 0.05
	}

	globalRatio := skinTotal / totalPixels
	centerRatio := centerSkin / math.Max(centerTotal, 1)
	meanGrad := skinGradientSum / skinTotal
	textureFactor := skinTransitions / skinTotal

	// Reject completely flat solid beige/tan images (meanGrad < 1.2)
	if meanGrad < 1.2 {
		return 0.10
	}

	// Logistic combination calibrated so normal clothed/portrait frames stay < 0.45
	// while high center-frame bare skin with natural body shading exceeds 0.75.
	z := -4.6 + 5.2*centerRatio + 2.8*globalRatio + 1.4*math.Min(textureFactor*2.0, 1.0)
	prob := 1.0 / (1.0 + math.Exp(-z))
	return math.Max(0, math.Min(1, prob))
}
