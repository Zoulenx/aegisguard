//go:build windows

package winprotect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"aegisguard/windows/internal/filter"
)

const (
	hostsPath        = `C:\Windows\System32\drivers\etc\hosts`
	hostsMarkerBegin = "# >>> AEGISGUARD-BEGIN (NO EDITAR) >>>"
	hostsMarkerEnd   = "# <<< AEGISGUARD-END <<<"
)

var (
	user32                 = syscall.NewLazyDLL("user32.dll")
	procGetForegroundWnd   = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW     = user32.NewProc("GetWindowTextW")
	procShowWindow         = user32.NewProc("ShowWindow")
	procPostMessageW       = user32.NewProc("PostMessageW")
	swMinimize             = uintptr(6)
	wmClose                = uintptr(0x0010)
)

// ApplyBrowserPolicies enforces SafeSearch, disables Incognito/Guest mode, disables built-in DoH bypass,
// and prepares extension policy keys for Chrome, Edge, and Brave via Windows Registry.
func ApplyBrowserPolicies(extensionDir string) error {
	browsers := []string{
		`HKLM\SOFTWARE\Policies\Google\Chrome`,
		`HKLM\SOFTWARE\Policies\Microsoft\Edge`,
		`HKLM\SOFTWARE\Policies\BraveSoftware\Brave`,
	}

	var errs []string
	for _, baseKey := range browsers {
		cmds := [][]string{
			{"add", baseKey, "/v", "ForceGoogleSafeSearch", "/t", "REG_DWORD", "/d", "1", "/f"},
			{"add", baseKey, "/v", "ForceYouTubeRestrict", "/t", "REG_DWORD", "/d", "2", "/f"},
			{"add", baseKey, "/v", "IncognitoModeAvailability", "/t", "REG_DWORD", "/d", "1", "/f"},
			{"add", baseKey, "/v", "BrowserGuestModeEnabled", "/t", "REG_DWORD", "/d", "0", "/f"},
			{"add", baseKey, "/v", "DnsOverHttpsMode", "/t", "REG_SZ", "/d", "off", "/f"},
			{"add", baseKey, "/v", "DeveloperToolsAvailability", "/t", "REG_DWORD", "/d", "2", "/f"},
		}
		for _, args := range cmds {
			cmd := exec.Command("reg.exe", args...)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			if out, err := cmd.CombinedOutput(); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v (%s)", baseKey, err, strings.TrimSpace(string(out))))
			}
		}
	}

	// Firefox Enterprise Policy JSON
	ffPolicyDir := `C:\Program Files\Mozilla Firefox\distribution`
	if _, err := os.Stat(`C:\Program Files\Mozilla Firefox`); err == nil {
		_ = os.MkdirAll(ffPolicyDir, 0755)
		policyJSON := `{
  "policies": {
    "DisablePrivateBrowsing": true,
    "DNSOverHTTPS": { "Enabled": false, "Locked": true },
    "SafeBrowsing": true,
    "BlockAboutConfig": true
  }
}`
		_ = os.WriteFile(filepath.Join(ffPolicyDir, "policies.json"), []byte(policyJSON), 0644)
	}

	if len(errs) > 0 {
		return fmt.Errorf("requiere privilegios de Administrador para algunas políticas: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ReconcileHostsFile writes and continuously guards the Windows hosts file with blocked adult & DoH domains.
func ReconcileHostsFile(domains []string) error {
	existingBytes, err := os.ReadFile(hostsPath)
	if err != nil {
		return err
	}
	existing := string(existingBytes)

	// Strip previous AegisGuard block if present
	if start := strings.Index(existing, hostsMarkerBegin); start >= 0 {
		if end := strings.Index(existing, hostsMarkerEnd); end > start {
			existing = strings.TrimSpace(existing[:start]) + "\r\n" + strings.TrimSpace(existing[end+len(hostsMarkerEnd):])
		}
	}

	var b strings.Builder
	b.WriteString(strings.TrimSpace(existing))
	b.WriteString("\r\n\r\n")
	b.WriteString(hostsMarkerBegin)
	b.WriteString("\r\n")
	for _, d := range domains {
		if strings.HasPrefix(d, ".") || d == "" {
			continue
		}
		b.WriteString("0.0.0.0 ")
		b.WriteString(d)
		b.WriteString("\r\n0.0.0.0 www.")
		b.WriteString(d)
		b.WriteString("\r\n")
	}
	b.WriteString(hostsMarkerEnd)
	b.WriteString("\r\n")

	return os.WriteFile(hostsPath, []byte(b.String()), 0644)
}

// StartDesktopContentGuard monitors active Windows desktop window titles & UI Automation text controls
// (browsers, Telegram Desktop, Discord, Store apps) and minimizes/blocks explicit searches in real time.
func StartDesktopContentGuard(ctx context.Context, sf *filter.SemanticFilter, onBlocked func(appTitle, reason string)) {
	go func() {
		ticker := time.NewTicker(1200 * time.Millisecond)
		defer ticker.Stop()
		var lastAlert time.Time

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				hwnd, title := getForegroundWindowTitle()
				if hwnd == 0 || title == "" {
					continue
				}
				// Never block AegisGuard's own dashboard
				if strings.Contains(strings.ToLower(title), "aegisguard") {
					continue
				}
				verdict := sf.Analyze(title)
				if verdict.Blocked {
					// Immediately minimize window and send close request for explicit window titles
					procShowWindow.Call(hwnd, swMinimize)
					if time.Since(lastAlert) > 3*time.Second {
						lastAlert = time.Now()
						if onBlocked != nil {
							onBlocked(title, verdict.Reason)
						}
					}
					continue
				}
			}
		}
	}()

	// Secondary UI Automation sampler (every 2.5s) reads focused Edit/Search boxes inside desktop apps (Telegram/Discord/Edge/Chrome).
	go func() {
		ticker := time.NewTicker(2500 * time.Millisecond)
		defer ticker.Stop()
		psScript := `
Add-Type -AssemblyName UIAutomationClient
$el = [System.Windows.Automation.AutomationElement]::FocusedElement
if ($el -ne $null) {
  $val = ""
  $vp = $null
  if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {
    $val = $vp.Current.Value
  }
  $name = $el.Current.Name
  Write-Output "$name|||$val"
}
`
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", psScript)
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				out, err := cmd.Output()
				if err != nil {
					continue
				}
				text := strings.TrimSpace(string(out))
				if text == "" || strings.Contains(strings.ToLower(text), "aegisguard") {
					continue
				}
				verdict := sf.Analyze(text)
				if verdict.Blocked {
					hwnd, title := getForegroundWindowTitle()
					if hwnd != 0 {
						procShowWindow.Call(hwnd, swMinimize)
						// Close offending explicit search tab/window when not a core OS shell
						if !strings.Contains(strings.ToLower(title), "explorer") {
							procPostMessageW.Call(hwnd, wmClose, 0, 0)
						}
					}
					if onBlocked != nil {
						onBlocked("UI-Input ("+title+")", verdict.Reason)
					}
				}
			}
		}
	}()
}

func getForegroundWindowTitle() (uintptr, string) {
	hwnd, _, _ := procGetForegroundWnd.Call()
	if hwnd == 0 {
		return 0, ""
	}
	buf := make([]uint16, 512)
	n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return hwnd, ""
	}
	return hwnd, syscall.UTF16ToString(buf[:n])
}

// ConfigureSystemDNS points active Windows network adapters to AegisGuard's local DNS filter (127.0.0.1).
func ConfigureSystemDNS() error {
	ps := `Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('127.0.0.1') }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error configurando DNS local (requiere Administrador): %v - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
