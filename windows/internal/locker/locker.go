package locker

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// Non-ambiguous characters for Extreme Friction Challenge (no 0/O, 1/I/l)
	frictionAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#%&*?!"
	frictionLength     = 180
	frictionMinSeconds = 90
	unlockWindowSecs   = 15 * 60
)

type NightSchedule struct {
	Enabled         bool `json:"enabled"`
	StartHour       int  `json:"start_hour"` // 0-23, e.g., 23
	EndHour         int  `json:"end_hour"`   // 0-23, e.g., 7
	BlockSocialApps bool `json:"block_social_apps"`
}

type CooldownRequest struct {
	Active         bool   `json:"active"`
	RequestedAtUTC int64  `json:"requested_at_utc"`
	UnlocksAtUTC   int64  `json:"unlocks_at_utc"`
	ExpiresAtUTC   int64  `json:"expires_at_utc"`
	Reason         string `json:"reason"`
}

type PartnerChallenge struct {
	ChallengeID  string `json:"challenge_id"`
	CreatedAtUTC int64  `json:"created_at_utc"`
	ExpiresAtUTC int64  `json:"expires_at_utc"`
}

type FrictionChallenge struct {
	ExpectedText string `json:"expected_text"`
	CreatedAtUTC int64  `json:"created_at_utc"`
	MinReadyUTC  int64  `json:"min_ready_utc"`
}

type AuditEntry struct {
	TimestampUTC int64  `json:"timestamp_utc"`
	Event        string `json:"event"`
	Detail       string `json:"detail"`
	PrevHash     string `json:"prev_hash"`
	Hash         string `json:"hash"`
}

type State struct {
	DeviceID             string             `json:"device_id"`
	CooldownHours        int                `json:"cooldown_hours"` // 24, 72, 168 (7 days)
	LockdownUntilUTC     int64              `json:"lockdown_until_utc"`
	PanicUntilUTC        int64              `json:"panic_until_utc"`
	UnlockedWindowUntil  int64              `json:"unlocked_window_until"`
	PartnerEnabled       bool               `json:"partner_enabled"`
	PartnerSecretHash    string             `json:"partner_secret_hash,omitempty"`
	PartnerSecret        string             `json:"partner_secret,omitempty"` // Kept encrypted/locked in protected data dir; never shown after setup
	FrictionRequired     bool               `json:"friction_required"`
	BlockSocialTriggers  bool               `json:"block_social_triggers"`
	NightSchedule        NightSchedule      `json:"night_schedule"`
	Cooldown             CooldownRequest    `json:"cooldown"`
	ActiveChallenge      *PartnerChallenge  `json:"active_challenge,omitempty"`
	ActiveFriction       *FrictionChallenge `json:"active_friction,omitempty"`
	LastTrustedUTC       int64              `json:"last_trusted_utc"`
	ClockTamperDetected  bool               `json:"clock_tamper_detected"`
	CustomDomains        []string           `json:"custom_domains"`
	CustomKeywords       []string           `json:"custom_keywords"`
	AuditLog             []AuditEntry       `json:"audit_log"`
}

// SyncBundle enables offline Windows <-> Android policy sync via QR/token.
// Convergence rule: always merges toward STRICTER protection (max lockdown, union of blocked rules).
type SyncBundle struct {
	Version             string        `json:"version"`
	SourceDeviceID      string        `json:"source_device_id"`
	GeneratedAtUTC      int64         `json:"generated_at_utc"`
	CooldownHours       int           `json:"cooldown_hours"`
	LockdownUntilUTC    int64         `json:"lockdown_until_utc"`
	BlockSocialTriggers bool          `json:"block_social_triggers"`
	NightSchedule       NightSchedule `json:"night_schedule"`
	CustomDomains       []string      `json:"custom_domains"`
	CustomKeywords      []string      `json:"custom_keywords"`
	Signature           string        `json:"signature"`
}

type Manager struct {
	mu       sync.RWMutex
	path     string
	state    State
	clock    TimeProvider
	minWait  int64 // default frictionMinSeconds (overridable in unit tests)
}

func NewManager(statePath string, clock TimeProvider) (*Manager, error) {
	if clock == nil {
		clock = NewNTPTimeProvider()
	}
	m := &Manager{
		path:    statePath,
		clock:   clock,
		minWait: frictionMinSeconds,
	}
	if err := m.loadOrInit(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) loadOrInit() error {
	if m.path != "" {
		if raw, err := os.ReadFile(m.path); err == nil {
			var st State
			if err := json.Unmarshal(raw, &st); err == nil && st.DeviceID != "" {
				m.state = st
				return nil
			}
		}
	}
	now, _ := m.clock.VerifiedUTC()
	m.state = State{
		DeviceID:            "AG-" + randomHex(6),
		CooldownHours:       72, // Default 72h cooldown — no quick bypass!
		BlockSocialTriggers: true,
		FrictionRequired:    true,
		NightSchedule: NightSchedule{
			Enabled:         true,
			StartHour:       23,
			EndHour:         7,
			BlockSocialApps: true,
		},
		LastTrustedUTC: now.Unix(),
	}
	m.appendAuditLocked(now.Unix(), "INIT", "AegisGuard inicializado en modo de alta protección (72h cooldown)")
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// verifiedNowLocked updates trusted clock and flags tampering if system time was rolled back or jumped without NTP.
func (m *Manager) verifiedNowLocked() (int64, bool) {
	t, fromNet := m.clock.VerifiedUTC()
	now := t.Unix()

	if fromNet {
		// Trusted NTP time clears tamper flag unless local clock is drastically skewed
		localDrift := now - time.Now().UTC().Unix()
		if localDrift < -120 || localDrift > 120 {
			m.state.ClockTamperDetected = true
			m.appendAuditLocked(now, "CLOCK_TAMPER", fmt.Sprintf("Desfase de reloj local detectado (%ds respecto a NTP)", localDrift))
		} else {
			m.state.ClockTamperDetected = false
		}
		if now > m.state.LastTrustedUTC {
			m.state.LastTrustedUTC = now
		}
		return now, true
	}

	// Offline check: detect backward clock rollback
	if now+120 < m.state.LastTrustedUTC {
		m.state.ClockTamperDetected = true
		m.appendAuditLocked(m.state.LastTrustedUTC, "CLOCK_TAMPER", "Intento de retroceso del reloj del sistema detectado")
		return m.state.LastTrustedUTC, false
	}
	if now > m.state.LastTrustedUTC {
		m.state.LastTrustedUTC = now
	}
	return now, false
}

func (m *Manager) Snapshot() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifiedNowLocked()
	cp := m.state
	cp.PartnerSecret = "" // Never expose raw partner secret in UI snapshots
	cp.AuditLog = append([]AuditEntry(nil), m.state.AuditLog...)
	cp.CustomDomains = append([]string(nil), m.state.CustomDomains...)
	cp.CustomKeywords = append([]string(nil), m.state.CustomKeywords...)
	return cp
}

// IsSettingsLocked returns true whenever weakening protection or uninstalling is prohibited.
func (m *Manager) IsSettingsLocked() (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, fromNet := m.verifiedNowLocked()

	if m.state.ClockTamperDetected {
		return true, "Manipulación de reloj detectada: desbloqueo congelado hasta sincronizar con NTP"
	}
	if m.state.LockdownUntilUTC > now {
		rem := time.Duration(m.state.LockdownUntilUTC-now) * time.Second
		return true, fmt.Sprintf("Modo Compromiso Estricto activo (restan %s)", formatDuration(rem))
	}
	if m.state.UnlockedWindowUntil > now {
		return false, "Ventana de modificación temporal abierta"
	}
	if m.state.Cooldown.Active && now >= m.state.Cooldown.UnlocksAtUTC && now <= m.state.Cooldown.ExpiresAtUTC {
		if !fromNet && m.state.ClockTamperDetected {
			return true, "Se requiere verificación de hora NTP para completar el enfriamiento"
		}
		if m.state.PartnerEnabled {
			return true, "Enfriamiento completado, pero se requiere código de Persona de Confianza"
		}
		if m.state.FrictionRequired {
			return true, "Enfriamiento completado, falta superar el Desafío de Fricción Extrema"
		}
		return false, "Enfriamiento completado"
	}
	return true, fmt.Sprintf("Protección activa (enfriamiento requerido: %dh)", m.state.CooldownHours)
}

// ShouldBlockSocialNow returns true during Panic Mode or Night Risk Hours.
func (m *Manager) ShouldBlockSocialNow() (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()

	if m.state.PanicUntilUTC > now {
		rem := time.Duration(m.state.PanicUntilUTC-now) * time.Second
		return true, fmt.Sprintf("Botón de Pánico activo (%s restantes)", formatDuration(rem))
	}
	if m.state.NightSchedule.Enabled && m.state.NightSchedule.BlockSocialApps {
		h := time.Now().Hour()
		start := m.state.NightSchedule.StartHour
		end := m.state.NightSchedule.EndHour
		inWindow := false
		if start > end {
			inWindow = h >= start || h < end
		} else if start < end {
			inWindow = h >= start && h < end
		}
		if inWindow {
			return true, fmt.Sprintf("Horario de Riesgo Nocturno (%02d:00-%02d:00)", start, end)
		}
	}
	return false, ""
}

// ActivatePanicMode immediately locks all social media and browsers for 30, 60, or 120 minutes.
// Strengthening protection NEVER requires unlocking.
func (m *Manager) ActivatePanicMode(minutes int) error {
	if minutes < 15 {
		minutes = 30
	}
	if minutes > 720 {
		minutes = 720
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	target := now + int64(minutes*60)
	if target > m.state.PanicUntilUTC {
		m.state.PanicUntilUTC = target
	}
	m.appendAuditLocked(now, "PANIC_MODE", fmt.Sprintf("Botón de Pánico activado por %d minutos", minutes))
	return m.saveLocked()
}

// EnableStrictLockdown locks the app with ZERO early unlock possibility until the chosen duration elapses.
func (m *Manager) EnableStrictLockdown(days int) error {
	if days < 1 || days > 365 {
		return errors.New("la duración del Modo Compromiso debe ser entre 1 y 365 días")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	target := now + int64(days*24*3600)
	if target <= m.state.LockdownUntilUTC {
		return errors.New("no se puede reducir un Modo Compromiso ya activo")
	}
	m.state.LockdownUntilUTC = target
	m.state.Cooldown = CooldownRequest{} // Cancel any pending cooldown
	m.state.UnlockedWindowUntil = 0
	m.appendAuditLocked(now, "LOCKDOWN_ENABLED", fmt.Sprintf("Modo Compromiso Estricto activado por %d días", days))
	return m.saveLocked()
}

// IncreaseCooldown allows strengthening cooldown duration anytime (only lowering requires unlock).
func (m *Manager) SetCooldownHours(hours int) error {
	if hours < 24 || hours > 720 {
		return errors.New("el enfriamiento mínimo es 24 horas y máximo 720 horas (30 días)")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	if hours < m.state.CooldownHours && m.state.UnlockedWindowUntil <= now {
		return errors.New("no puedes reducir las horas de enfriamiento mientras la protección está bloqueada")
	}
	m.state.CooldownHours = hours
	m.appendAuditLocked(now, "COOLDOWN_CONFIG", fmt.Sprintf("Enfriamiento configurado a %d horas", hours))
	return m.saveLocked()
}

// AddProtectionRules allows adding custom domains or keywords immediately (hardening never needs unlock).
func (m *Manager) AddProtectionRules(domains, keywords []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	m.state.CustomDomains = unionStrings(m.state.CustomDomains, domains)
	m.state.CustomKeywords = unionStrings(m.state.CustomKeywords, keywords)
	m.appendAuditLocked(now, "RULES_HARDENED", fmt.Sprintf("Reglas reforzadas (+%d dominios, +%d palabras)", len(domains), len(keywords)))
	return m.saveLocked()
}

// SetupAccountabilityPartner generates a 256-bit secret to hand to a trusted partner (shown ONCE).
func (m *Manager) SetupAccountabilityPartner() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	if m.state.PartnerEnabled && m.state.UnlockedWindowUntil <= now {
		return "", errors.New("ya existe una Persona de Confianza activa; se requiere su aprobación para cambiarla")
	}
	secret := strings.ToUpper(randomHex(16)) // 32 hex chars (128-bit high-entropy printable key)
	sum := sha256.Sum256([]byte(secret))
	m.state.PartnerEnabled = true
	m.state.PartnerSecret = secret
	m.state.PartnerSecretHash = hex.EncodeToString(sum[:])
	m.appendAuditLocked(now, "PARTNER_SETUP", "Protección con Persona de Confianza activada")
	if err := m.saveLocked(); err != nil {
		return "", err
	}
	return secret, nil
}

// ComputePartnerApprovalCode implements the shared HMAC-SHA256 protocol (Windows & Android compatible).
func ComputePartnerApprovalCode(partnerSecret, deviceID, challengeID string) string {
	mac := hmac.New(sha256.New, []byte(strings.ToUpper(strings.TrimSpace(partnerSecret))))
	msg := fmt.Sprintf("AEGIS-UNLOCK-V1|%s|%s", strings.TrimSpace(deviceID), strings.ToUpper(strings.TrimSpace(challengeID)))
	mac.Write([]byte(msg))
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))[:12]
}

// RequestCooldownUnlock begins the mandatory waiting period (cannot be accelerated, can always be canceled).
func (m *Manager) RequestCooldownUnlock(reason string) (CooldownRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	if m.state.LockdownUntilUTC > now {
		return CooldownRequest{}, errors.New("imposible solicitar desbloqueo durante el Modo Compromiso Estricto")
	}
	if m.state.Cooldown.Active && now < m.state.Cooldown.ExpiresAtUTC {
		return m.state.Cooldown, nil
	}
	waitSecs := int64(m.state.CooldownHours) * 3600
	req := CooldownRequest{
		Active:         true,
		RequestedAtUTC: now,
		UnlocksAtUTC:   now + waitSecs,
		ExpiresAtUTC:   now + waitSecs + unlockWindowSecs,
		Reason:         strings.TrimSpace(reason),
	}
	m.state.Cooldown = req
	m.appendAuditLocked(now, "UNLOCK_REQUESTED", fmt.Sprintf("Solicitud de enfriamiento iniciada (%dh). Motivo: %s", m.state.CooldownHours, req.Reason))
	return req, m.saveLocked()
}

// CancelCooldownUnlock lets the user immediately cancel a pending unlock request (1 click).
func (m *Manager) CancelCooldownUnlock() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	m.state.Cooldown = CooldownRequest{}
	m.state.ActiveChallenge = nil
	m.state.ActiveFriction = nil
	m.appendAuditLocked(now, "UNLOCK_CANCELED", "Solicitud de desbloqueo cancelada por el usuario")
	return m.saveLocked()
}

// StartPartnerChallenge creates a 30-minute one-time challenge ID to send to the accountability partner.
func (m *Manager) StartPartnerChallenge() (PartnerChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	if m.state.LockdownUntilUTC > now {
		return PartnerChallenge{}, errors.New("Modo Compromiso Estricto activo")
	}
	if !m.state.PartnerEnabled {
		return PartnerChallenge{}, errors.New("Persona de Confianza no configurada")
	}
	ch := PartnerChallenge{
		ChallengeID:  strings.ToUpper(randomHex(6)),
		CreatedAtUTC: now,
		ExpiresAtUTC: now + 30*60,
	}
	m.state.ActiveChallenge = &ch
	m.appendAuditLocked(now, "PARTNER_CHALLENGE", "Reto generado para Persona de Confianza: "+ch.ChallengeID)
	return ch, m.saveLocked()
}

// VerifyPartnerCode validates the HMAC code supplied by the accountability partner and opens a 15-min window.
func (m *Manager) VerifyPartnerCode(code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	if m.state.LockdownUntilUTC > now {
		return errors.New("Modo Compromiso Estricto activo")
	}
	if m.state.ActiveChallenge == nil || now > m.state.ActiveChallenge.ExpiresAtUTC {
		return errors.New("no hay un reto activo o ya expiró")
	}
	expected := ComputePartnerApprovalCode(m.state.PartnerSecret, m.state.DeviceID, m.state.ActiveChallenge.ChallengeID)
	provided := strings.ToUpper(strings.TrimSpace(code))
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		m.appendAuditLocked(now, "PARTNER_CODE_FAILED", "Código de Persona de Confianza incorrecto")
		_ = m.saveLocked()
		return errors.New("código de aprobación inválido")
	}
	m.state.UnlockedWindowUntil = now + unlockWindowSecs
	m.state.ActiveChallenge = nil
	m.state.Cooldown = CooldownRequest{}
	m.appendAuditLocked(now, "PARTNER_UNLOCKED", "Ventana de modificación de 15 min aprobada por Persona de Confianza")
	return m.saveLocked()
}

// StartFrictionChallenge generates a 180-character random non-ambiguous string with mandatory minimum typing wait.
func (m *Manager) StartFrictionChallenge() (FrictionChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	if m.state.LockdownUntilUTC > now {
		return FrictionChallenge{}, errors.New("Modo Compromiso Estricto activo")
	}
	if m.state.PartnerEnabled {
		return FrictionChallenge{}, errors.New("este dispositivo exige aprobación de Persona de Confianza")
	}
	if !m.state.Cooldown.Active || now < m.state.Cooldown.UnlocksAtUTC {
		return FrictionChallenge{}, errors.New("primero debe completarse el temporizador de enfriamiento")
	}
	fc := FrictionChallenge{
		ExpectedText: randomFromAlphabet(frictionAlphabet, frictionLength),
		CreatedAtUTC: now,
		MinReadyUTC:  now + m.minWait,
	}
	m.state.ActiveFriction = &fc
	m.appendAuditLocked(now, "FRICTION_STARTED", "Desafío de fricción extrema (180 caracteres) iniciado")
	return fc, m.saveLocked()
}

// VerifyFrictionChallenge enforces minimum dwell time AND exact manual typing (>=98% accuracy).
func (m *Manager) VerifyFrictionChallenge(typed string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	if m.state.ActiveFriction == nil {
		return errors.New("no hay desafío de fricción activo")
	}
	if now < m.state.ActiveFriction.MinReadyUTC {
		rem := m.state.ActiveFriction.MinReadyUTC - now
		return fmt.Errorf("demasiado rápido (posible copia/pega): espera %d segundos más", rem)
	}
	exp := m.state.ActiveFriction.ExpectedText
	if len(typed) != len(exp) {
		return fmt.Errorf("longitud incorrecta (%d/%d caracteres)", len(typed), len(exp))
	}
	mismatches := 0
	for i := range exp {
		if typed[i] != exp[i] {
			mismatches++
		}
	}
	maxErrors := len(exp) / 50 // < 2% error tolerance (3 chars out of 180)
	if mismatches > maxErrors {
		return fmt.Errorf("demasiados errores (%d fallos, máximo permitido %d)", mismatches, maxErrors)
	}
	m.state.UnlockedWindowUntil = now + unlockWindowSecs
	m.state.ActiveFriction = nil
	m.state.Cooldown = CooldownRequest{}
	m.appendAuditLocked(now, "FRICTION_UNLOCKED", "Ventana de modificación de 15 min abierta tras enfriamiento + fricción")
	return m.saveLocked()
}

// ExportSyncToken produces a Base64URL signed policy bundle for syncing Windows <-> Android.
func (m *Manager) ExportSyncToken(sharedKey string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	bundle := SyncBundle{
		Version:             "1.0",
		SourceDeviceID:      m.state.DeviceID,
		GeneratedAtUTC:      now,
		CooldownHours:       m.state.CooldownHours,
		LockdownUntilUTC:    m.state.LockdownUntilUTC,
		BlockSocialTriggers: m.state.BlockSocialTriggers,
		NightSchedule:       m.state.NightSchedule,
		CustomDomains:       append([]string(nil), m.state.CustomDomains...),
		CustomKeywords:      append([]string(nil), m.state.CustomKeywords...),
	}
	bundle.Signature = signSyncBundle(bundle, sharedKey)
	raw, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ImportSyncToken merges rules from another device strictly toward HIGHER protection.
func (m *Manager) ImportSyncToken(token, sharedKey string) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return errors.New("token de sincronización inválido")
	}
	var bundle SyncBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return errors.New("formato de paquete de sincronización inválido")
	}
	expectedSig := signSyncBundle(bundle, sharedKey)
	if !hmac.Equal([]byte(expectedSig), []byte(bundle.Signature)) {
		return errors.New("firma criptográfica de sincronización inválida")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()

	// Strict convergence: always keep the stronger setting
	if bundle.CooldownHours > m.state.CooldownHours {
		m.state.CooldownHours = bundle.CooldownHours
	}
	if bundle.LockdownUntilUTC > m.state.LockdownUntilUTC {
		m.state.LockdownUntilUTC = bundle.LockdownUntilUTC
	}
	if bundle.BlockSocialTriggers {
		m.state.BlockSocialTriggers = true
	}
	if bundle.NightSchedule.Enabled {
		m.state.NightSchedule = bundle.NightSchedule
	}
	m.state.CustomDomains = unionStrings(m.state.CustomDomains, bundle.CustomDomains)
	m.state.CustomKeywords = unionStrings(m.state.CustomKeywords, bundle.CustomKeywords)

	m.appendAuditLocked(now, "SYNC_IMPORTED", "Reglas sincronizadas desde dispositivo "+bundle.SourceDeviceID)
	return m.saveLocked()
}

// VerifyAuditChain checks whether any entry in the audit log was altered or deleted.
func (m *Manager) VerifyAuditChain() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prev := "GENESIS"
	for _, entry := range m.state.AuditLog {
		if entry.PrevHash != prev {
			return false
		}
		expected := computeAuditHash(entry.TimestampUTC, entry.Event, entry.Detail, entry.PrevHash)
		if entry.Hash != expected {
			return false
		}
		prev = entry.Hash
	}
	return true
}

func (m *Manager) RecordBlockEvent(eventType, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, _ := m.verifiedNowLocked()
	m.appendAuditLocked(now, eventType, detail)
	_ = m.saveLocked()
}

func (m *Manager) appendAuditLocked(ts int64, event, detail string) {
	prev := "GENESIS"
	if n := len(m.state.AuditLog); n > 0 {
		prev = m.state.AuditLog[n-1].Hash
	}
	entry := AuditEntry{
		TimestampUTC: ts,
		Event:        event,
		Detail:       detail,
		PrevHash:     prev,
		Hash:         computeAuditHash(ts, event, detail, prev),
	}
	m.state.AuditLog = append(m.state.AuditLog, entry)
	// Keep last 500 entries while preserving chain head if rotated
	if len(m.state.AuditLog) > 500 {
		m.state.AuditLog = m.state.AuditLog[len(m.state.AuditLog)-500:]
		m.state.AuditLog[0].PrevHash = "GENESIS"
		for i := range m.state.AuditLog {
			if i > 0 {
				m.state.AuditLog[i].PrevHash = m.state.AuditLog[i-1].Hash
			}
			m.state.AuditLog[i].Hash = computeAuditHash(
				m.state.AuditLog[i].TimestampUTC,
				m.state.AuditLog[i].Event,
				m.state.AuditLog[i].Detail,
				m.state.AuditLog[i].PrevHash,
			)
		}
	}
}

func computeAuditHash(ts int64, event, detail, prev string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s", ts, event, detail, prev)))
	return hex.EncodeToString(h[:])[:16]
}

func signSyncBundle(b SyncBundle, key string) string {
	b.Signature = ""
	payload, _ := json.Marshal(b)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomFromAlphabet(alphabet string, length int) string {
	buf := make([]byte, length)
	_, _ = rand.Read(buf)
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		out[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(out)
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, list := range [][]string{a, b} {
		for _, item := range list {
			item = strings.TrimSpace(strings.ToLower(item))
			if item == "" {
				continue
			}
			if _, ok := seen[item]; !ok {
				seen[item] = struct{}{}
				out = append(out, item)
			}
		}
	}
	return out
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		return "0m"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}
