package locker

import (
	"path/filepath"
	"testing"
	"time"
)

type fakeClock struct {
	now     time.Time
	fromNet bool
}

func (f *fakeClock) VerifiedUTC() (time.Time, bool) {
	return f.now, f.fromNet
}

func TestCooldownAndFrictionUnlock(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{now: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC), fromNet: false}
	mgr, err := NewManager(filepath.Join(dir, "state.json"), clk)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	mgr.minWait = 90

	// Initially locked (default 72h cooldown)
	if locked, _ := mgr.IsSettingsLocked(); !locked {
		t.Fatalf("expected locked initially")
	}

	// Cannot reduce cooldown while locked
	if err := mgr.SetCooldownHours(24); err == nil {
		t.Fatalf("expected error reducing cooldown while locked")
	}

	// Request cooldown unlock
	req, err := mgr.RequestCooldownUnlock("Necesito ajustar reglas")
	if err != nil {
		t.Fatalf("RequestCooldownUnlock failed: %v", err)
	}
	if !req.Active {
		t.Fatalf("expected cooldown active")
	}

	// Advance only 48 hours -> still locked, cannot start friction challenge
	clk.now = clk.now.Add(48 * time.Hour)
	if _, err := mgr.StartFrictionChallenge(); err == nil {
		t.Fatalf("expected friction challenge rejected before cooldown finishes")
	}

	// Advance to 72h + 1m -> cooldown elapsed, start friction challenge
	clk.now = clk.now.Add(24*time.Hour + time.Minute)
	fc, err := mgr.StartFrictionChallenge()
	if err != nil {
		t.Fatalf("StartFrictionChallenge failed: %v", err)
	}
	if len(fc.ExpectedText) != frictionLength {
		t.Fatalf("expected %d chars, got %d", frictionLength, len(fc.ExpectedText))
	}

	// Submitting immediately (paste cheat) must fail
	if err := mgr.VerifyFrictionChallenge(fc.ExpectedText); err == nil {
		t.Fatalf("expected fast submit (paste cheat) to be rejected")
	}

	// Advance 95s and submit exact text -> unlocks 15-min window
	clk.now = clk.now.Add(95 * time.Second)
	if err := mgr.VerifyFrictionChallenge(fc.ExpectedText); err != nil {
		t.Fatalf("VerifyFrictionChallenge failed: %v", err)
	}
	if locked, _ := mgr.IsSettingsLocked(); locked {
		t.Fatalf("expected temporary unlock window open")
	}
	if !mgr.VerifyAuditChain() {
		t.Fatalf("audit chain verification failed")
	}
}

func TestAccountabilityPartnerAndLockdown(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{now: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC), fromNet: false}
	mgr, err := NewManager(filepath.Join(dir, "state.json"), clk)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	secret, err := mgr.SetupAccountabilityPartner()
	if err != nil {
		t.Fatalf("SetupAccountabilityPartner failed: %v", err)
	}

	ch, err := mgr.StartPartnerChallenge()
	if err != nil {
		t.Fatalf("StartPartnerChallenge failed: %v", err)
	}

	// Wrong code fails
	if err := mgr.VerifyPartnerCode("WRONG0000000"); err == nil {
		t.Fatalf("expected wrong partner code to fail")
	}

	// Valid HMAC code succeeds
	validCode := ComputePartnerApprovalCode(secret, mgr.Snapshot().DeviceID, ch.ChallengeID)
	if err := mgr.VerifyPartnerCode(validCode); err != nil {
		t.Fatalf("expected valid partner code to succeed: %v", err)
	}
	if locked, _ := mgr.IsSettingsLocked(); locked {
		t.Fatalf("expected unlock window after partner code")
	}

	// Enable 15-day Strict Lockdown -> immediately locks everything, even partner challenge blocked
	if err := mgr.EnableStrictLockdown(15); err != nil {
		t.Fatalf("EnableStrictLockdown failed: %v", err)
	}
	if locked, _ := mgr.IsSettingsLocked(); !locked {
		t.Fatalf("expected locked during Strict Lockdown")
	}
	if _, err := mgr.RequestCooldownUnlock("test"); err == nil {
		t.Fatalf("expected cooldown request rejected during Strict Lockdown")
	}
}

func TestClockRollbackTamperAndSyncConvergence(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{now: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC), fromNet: false}
	mgrA, _ := NewManager(filepath.Join(dir, "a.json"), clk)
	mgrB, _ := NewManager(filepath.Join(dir, "b.json"), clk)

	// Clock rollback detection
	clk.now = clk.now.Add(-2 * time.Hour)
	snap := mgrA.Snapshot()
	if !snap.ClockTamperDetected {
		t.Fatalf("expected clock tamper detected on 2h rollback")
	}

	// Sync bundle convergence toward stricter rules
	clk.now = time.Date(2026, 11, 19, 13, 0, 0, 0, time.UTC)
	_ = mgrA.EnableStrictLockdown(30)
	_ = mgrA.AddProtectionRules([]string{"sitio-extra.com"}, []string{"palabraextra"})

	token, err := mgrA.ExportSyncToken("clave-sincro-compartida")
	if err != nil {
		t.Fatalf("ExportSyncToken failed: %v", err)
	}
	if err := mgrB.ImportSyncToken(token, "clave-sincro-compartida"); err != nil {
		t.Fatalf("ImportSyncToken failed: %v", err)
	}
	snapB := mgrB.Snapshot()
	if snapB.LockdownUntilUTC < mgrA.Snapshot().LockdownUntilUTC {
		t.Fatalf("expected device B to adopt stricter 30-day lockdown")
	}
	if len(snapB.CustomDomains) != 1 || snapB.CustomDomains[0] != "sitio-extra.com" {
		t.Fatalf("expected custom domains merged, got %v", snapB.CustomDomains)
	}
}
