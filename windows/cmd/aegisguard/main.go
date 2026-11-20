package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"aegisguard/windows/internal/dnsproxy"
	"aegisguard/windows/internal/filter"
	"aegisguard/windows/internal/locker"
	"aegisguard/windows/internal/rules"
	"aegisguard/windows/internal/ui"
	"aegisguard/windows/internal/vision"
	"aegisguard/windows/internal/winprotect"
)

func main() {
	if len(os.Args) < 2 {
		runDaemon(os.Args[1:])
		return
	}

	switch os.Args[1] {
	case "run":
		runDaemon(os.Args[2:])
	case "partner-approve":
		runPartnerApprove(os.Args[2:])
	case "test-text":
		runTestText(os.Args[2:])
	case "apply-policies":
		if err := winprotect.ApplyBrowserPolicies(""); err != nil {
			log.Fatalf("Error aplicando políticas: %v", err)
		}
		fmt.Println("Políticas de navegadores aplicadas correctamente.")
	case "help", "-h", "--help":
		printUsage()
	default:
		runDaemon(os.Args[1:])
	}
}

func printUsage() {
	fmt.Println(`AegisGuard v1.1 — Bloqueador Estricto con IA Visual Local (Windows)

Uso:
  aegisguard run [--dns 127.0.0.1:53] [--ui 127.0.0.1:18492] [--ai http://127.0.0.1:18493] [--data-dir <ruta>] [--apply-os]
  aegisguard partner-approve --secret <CLAVE> --device <DEVICE_ID> --challenge <RETO_ID>
  aegisguard test-text "<texto o busqueda a analizar>"
  aegisguard apply-policies`)
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dnsAddr := fs.String("dns", "127.0.0.1:53", "Dirección UDP del servidor DNS de filtrado")
	uiAddr := fs.String("ui", "127.0.0.1:18492", "Dirección HTTP del panel de control local")
	aiAddr := fs.String("ai", "http://127.0.0.1:18493", "Endpoint local del motor neuronal ONNX (aegisguard-ai.exe)")
	dataDir := fs.String("data-dir", defaultDataDir(), "Directorio de datos protegidos")
	applyOS := fs.Bool("apply-os", false, "Aplicar hosts, DNS del sistema y políticas de navegador (requiere Admin)")
	_ = fs.Parse(args)

	blocklist, err := rules.LoadEmbeddedBlocklist()
	if err != nil {
		log.Fatalf("error cargando blocklist: %v", err)
	}
	kwRules, err := rules.LoadEmbeddedKeywords()
	if err != nil {
		log.Fatalf("error cargando palabras clave: %v", err)
	}
	socialRules, err := rules.LoadEmbeddedSocialApps()
	if err != nil {
		log.Fatalf("error cargando reglas sociales: %v", err)
	}

	statePath := filepath.Join(*dataDir, "aegis_state.json")
	lockMgr, err := locker.NewManager(statePath, locker.NewNTPTimeProvider())
	if err != nil {
		log.Fatalf("error inicializando LockManager: %v", err)
	}

	semFilter := filter.NewSemanticFilter(kwRules)
	domFilter := filter.NewDomainFilter(blocklist, socialRules, semFilter)
	domFilter.SetSocialBlockHook(lockMgr.ShouldBlockSocialNow)

	// Apply persisted user-hardened rules
	snap := lockMgr.Snapshot()
	semFilter.AddCustomTerms(snap.CustomKeywords)
	for _, d := range snap.CustomDomains {
		domFilter.AddCustomDomain(d)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start Local DNS Filtering Proxy
	dnsSrv := dnsproxy.NewServer(*dnsAddr, domFilter)
	dnsSrv.OnEvent = func(ev dnsproxy.QueryEvent) {
		if ev.Action == "BLOCK" {
			log.Printf("[DNS-BLOCK] %s -> %s", ev.Domain, ev.Reason)
			lockMgr.RecordBlockEvent("DNS_BLOCK", ev.Domain+" ("+ev.Reason+")")
		}
	}
	boundDNS, err := dnsSrv.Start(ctx)
	if err != nil {
		log.Printf("[AVISO] No se pudo enlazar DNS en %s (%v). Ejecuta como Administrador para usar puerto 53.", *dnsAddr, err)
	} else {
		log.Printf("[OK] Filtro DNS activo en %s (Upstream: 1.1.1.3 / CleanBrowsing)", boundDNS)
	}

	// Start 100% Local Visual AI Screen Scanner (ResNet-50 ONNX sidecar + pure-Go fallback)
	visionEng := vision.NewEngine(*aiAddr)
	visionEng.StartGuard(ctx, 2500*time.Millisecond, func(windowTitle string, v vision.Verdict) {
		log.Printf("[VISUAL-AI-BLOCK] ventana=%q motor=%s conf=%.0f%%", windowTitle, v.Engine, v.Confidence*100)
		lockMgr.RecordBlockEvent("VISUAL_NSFW_BLOCK", fmt.Sprintf("%s -> %s", windowTitle, v.Reason))
	})
	log.Printf("[OK] IA Visual 100%% local iniciada (endpoint ONNX: %s)", *aiAddr)

	// Start Embedded Local Dashboard
	dash := &ui.Dashboard{
		ListenAddr: *uiAddr,
		Locker:     lockMgr,
		DNS:        dnsSrv,
		Domain:     domFilter,
		Semantic:   semFilter,
		Vision:     visionEng,
	}
	boundUI, err := dash.Start(ctx)
	if err != nil {
		log.Fatalf("error iniciando panel local: %v", err)
	}
	log.Printf("[OK] Panel de control AegisGuard v1.1 disponible en http://%s", boundUI)

	// Start Windows Desktop Content Guard (window titles & UI Automation inputs)
	winprotect.StartDesktopContentGuard(ctx, semFilter, func(appTitle, reason string) {
		log.Printf("[DESKTOP-BLOCK] %s -> %s", appTitle, reason)
		lockMgr.RecordBlockEvent("DESKTOP_BLOCK", appTitle+": "+reason)
	})

	// Optional Windows OS hardening + continuous hosts reconciliation
	if *applyOS {
		if err := winprotect.ApplyBrowserPolicies(""); err != nil {
			log.Printf("[AVISO] Políticas de navegador: %v", err)
		}
		if err := winprotect.ReconcileHostsFile(domFilter.BlockedDomainsList()); err != nil {
			log.Printf("[AVISO] Archivo hosts: %v", err)
		}
		if err := winprotect.ConfigureSystemDNS(); err != nil {
			log.Printf("[AVISO] DNS del sistema: %v", err)
		}
		go func() {
			t := time.NewTicker(60 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					_ = winprotect.ReconcileHostsFile(domFilter.BlockedDomainsList())
				}
			}
		}()
	}

	<-ctx.Done()
	log.Println("AegisGuard detenido.")
}

func runPartnerApprove(args []string) {
	fs := flag.NewFlagSet("partner-approve", flag.ExitOnError)
	secret := fs.String("secret", "", "Clave secreta de la Persona de Confianza")
	device := fs.String("device", "", "ID del dispositivo (ej: AG-XXXXXX)")
	challenge := fs.String("challenge", "", "ID del reto generado por el dispositivo")
	_ = fs.Parse(args)
	if *secret == "" || *device == "" || *challenge == "" {
		log.Fatal("Debes indicar --secret, --device y --challenge")
	}
	code := locker.ComputePartnerApprovalCode(*secret, *device, *challenge)
	fmt.Printf("Código de aprobación HMAC (válido para este reto único): %s\n", code)
}

func runTestText(args []string) {
	if len(args) == 0 {
		log.Fatal("Indica un texto a analizar")
	}
	kwRules, _ := rules.LoadEmbeddedKeywords()
	sf := filter.NewSemanticFilter(kwRules)
	v := sf.Analyze(args[0])
	fmt.Printf("Blocked=%v Warning=%v Score=%d Matched=%v Reason=%q\n", v.Blocked, v.Warning, v.Score, v.MatchedTerms, v.Reason)
}

func defaultDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "AegisGuard")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aegisguard")
}
