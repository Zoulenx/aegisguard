package ui

import (
	"context"
	"embed"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"aegisguard/windows/internal/dnsproxy"
	"aegisguard/windows/internal/filter"
	"aegisguard/windows/internal/locker"
	"aegisguard/windows/internal/vision"
)

//go:embed static/index.html
var staticFS embed.FS

type Dashboard struct {
	ListenAddr string
	Locker     *locker.Manager
	DNS        *dnsproxy.Server
	Domain     *filter.DomainFilter
	Semantic   *filter.SemanticFilter
	Vision     *vision.Engine
}

func (d *Dashboard) Start(ctx context.Context) (string, error) {
	if d.ListenAddr == "" {
		d.ListenAddr = "127.0.0.1:18492"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/api/status", d.handleStatus)
	mux.HandleFunc("/api/panic", d.handlePanic)
	mux.HandleFunc("/api/lockdown", d.handleLockdown)
	mux.HandleFunc("/api/cooldown/request", d.handleCooldownReq)
	mux.HandleFunc("/api/cooldown/cancel", d.handleCooldownCancel)
	mux.HandleFunc("/api/friction/start", d.handleFrictionStart)
	mux.HandleFunc("/api/friction/verify", d.handleFrictionVerify)
	mux.HandleFunc("/api/partner/setup", d.handlePartnerSetup)
	mux.HandleFunc("/api/partner/challenge", d.handlePartnerChallenge)
	mux.HandleFunc("/api/partner/verify", d.handlePartnerVerify)
	mux.HandleFunc("/api/test", d.handleTest)
	mux.HandleFunc("/api/rules/add", d.handleAddRules)
	mux.HandleFunc("/api/sync/export", d.handleSyncExport)
	mux.HandleFunc("/api/sync/import", d.handleSyncImport)
	mux.HandleFunc("/api/vision/threshold", d.handleVisionThreshold)

	ln, err := net.Listen("tcp", d.ListenAddr)
	if err != nil {
		return "", err
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()
	go func() {
		_ = srv.Serve(ln)
	}()
	return ln.Addr().String(), nil
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "dashboard missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (d *Dashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	locked, reason := d.Locker.IsSettingsLocked()
	var blocked, allowed, safe uint64
	if d.DNS != nil {
		blocked, allowed, safe = d.DNS.Stats()
	}
	var vis vision.Stats
	if d.Vision != nil {
		vis = d.Vision.Stats()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":      "1.1.0",
		"locked":       locked,
		"lock_reason":  reason,
		"audit_valid":  d.Locker.VerifyAuditChain(),
		"state":        d.Locker.Snapshot(),
		"vision_stats": vis,
		"dns_stats": map[string]uint64{
			"blocked":    blocked,
			"allowed":    allowed,
			"safesearch": safe,
		},
	})
}

func (d *Dashboard) handleVisionThreshold(w http.ResponseWriter, r *http.Request) {
	if d.Vision == nil {
		writeErr(w, http.StatusServiceUnavailable, "IA Visual no inicializada")
		return
	}
	var req struct {
		Threshold float64 `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	cur := d.Vision.Stats().Threshold
	locked, _ := d.Locker.IsSettingsLocked()
	// Solo permite hacer el umbral más estricto (más bajo) mientras está bloqueado
	if locked && req.Threshold > cur {
		writeErr(w, http.StatusForbidden, "No puedes relajar la sensibilidad de la IA Visual mientras la protección está bloqueada")
		return
	}
	d.Vision.SetThreshold(req.Threshold)
	d.Locker.RecordBlockEvent("VISION_CONFIG", "Umbral IA Visual actualizado")
	writeJSON(w, http.StatusOK, d.Vision.Stats())
}

func (d *Dashboard) handlePanic(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Minutes int `json:"minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if err := d.Locker.ActivatePanicMode(req.Minutes); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *Dashboard) handleLockdown(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Days int `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if err := d.Locker.EnableStrictLockdown(req.Days); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *Dashboard) handleCooldownReq(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	cd, err := d.Locker.RequestCooldownUnlock(req.Reason)
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cd)
}

func (d *Dashboard) handleCooldownCancel(w http.ResponseWriter, r *http.Request) {
	if err := d.Locker.CancelCooldownUnlock(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *Dashboard) handleFrictionStart(w http.ResponseWriter, r *http.Request) {
	fc, err := d.Locker.StartFrictionChallenge()
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fc)
}

func (d *Dashboard) handleFrictionVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Typed string `json:"typed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if err := d.Locker.VerifyFrictionChallenge(req.Typed); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *Dashboard) handlePartnerSetup(w http.ResponseWriter, r *http.Request) {
	secret, err := d.Locker.SetupAccountabilityPartner()
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"partner_secret": secret})
}

func (d *Dashboard) handlePartnerChallenge(w http.ResponseWriter, r *http.Request) {
	ch, err := d.Locker.StartPartnerChallenge()
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":    d.Locker.Snapshot().DeviceID,
		"challenge_id": ch.ChallengeID,
		"expires_at":   ch.ExpiresAtUTC,
	})
}

func (d *Dashboard) handlePartnerVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if err := d.Locker.VerifyPartnerCode(req.Code); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *Dashboard) handleTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Input string `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	tv := d.Semantic.Analyze(req.Input)
	dd := d.Domain.Evaluate(req.Input)
	writeJSON(w, http.StatusOK, map[string]any{
		"text_verdict":    tv,
		"domain_decision": dd,
	})
}

func (d *Dashboard) handleAddRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains  []string `json:"domains"`
		Keywords []string `json:"keywords"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if err := d.Locker.AddProtectionRules(req.Domains, req.Keywords); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, dom := range req.Domains {
		d.Domain.AddCustomDomain(dom)
	}
	d.Semantic.AddCustomTerms(req.Keywords)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *Dashboard) handleSyncExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Key) < 6 {
		writeErr(w, http.StatusBadRequest, "La clave compartida debe tener al menos 6 caracteres")
		return
	}
	tok, err := d.Locker.ExportSyncToken(req.Key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func (d *Dashboard) handleSyncImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key   string `json:"key"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" || req.Token == "" {
		writeErr(w, http.StatusBadRequest, "Clave y token requeridos")
		return
	}
	if err := d.Locker.ImportSyncToken(req.Token, req.Key); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	snap := d.Locker.Snapshot()
	for _, dom := range snap.CustomDomains {
		d.Domain.AddCustomDomain(dom)
	}
	d.Semantic.AddCustomTerms(snap.CustomKeywords)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
