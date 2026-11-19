//go:build !windows

package winprotect

import (
	"context"
	"errors"

	"aegisguard/windows/internal/filter"
)

func ApplyBrowserPolicies(extensionDir string) error {
	return errors.New("las políticas de Registro de Windows solo se aplican al ejecutar en Windows")
}

func ReconcileHostsFile(domains []string) error {
	return nil
}

func StartDesktopContentGuard(ctx context.Context, sf *filter.SemanticFilter, onBlocked func(appTitle, reason string)) {
	// Desktop Win32/UIAutomation guard runs on Windows builds.
}

func ConfigureSystemDNS() error {
	return errors.New("la configuración de adaptadores DNS de Windows solo aplica en Windows")
}
