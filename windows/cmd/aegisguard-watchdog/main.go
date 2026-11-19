package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// aegisguard-watchdog monitors the main AegisGuard daemon continuously.
// If the daemon is killed or stops responding, the watchdog relaunches it within seconds.
func main() {
	healthURL := flag.String("health-url", "http://127.0.0.1:18492/api/status", "URL local de salud del demonio principal")
	binPath := flag.String("bin", "", "Ruta al ejecutable principal aegisguard.exe")
	applyOS := flag.Bool("apply-os", true, "Pasar --apply-os al relanzar")
	interval := flag.Duration("interval", 5*time.Second, "Intervalo de vigilancia")
	flag.Parse()

	targetBin := *binPath
	if targetBin == "" {
		exe, _ := os.Executable()
		name := "aegisguard"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		targetBin = filepath.Join(filepath.Dir(exe), name)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	log.Printf("[WATCHDOG] Vigilando %s (salud: %s cada %s)", targetBin, *healthURL, interval.String())

	failures := 0
	for {
		resp, err := client.Get(*healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			failures = 0
		} else {
			if resp != nil {
				_ = resp.Body.Close()
			}
			failures++
			if failures >= 2 {
				log.Printf("[WATCHDOG] Demonio principal caído o bloqueado -> Relanzando %s", targetBin)
				args := []string{"run"}
				if *applyOS {
					args = append(args, "--apply-os")
				}
				cmd := exec.Command(targetBin, args...)
				if err := cmd.Start(); err != nil {
					log.Printf("[WATCHDOG] Error relanzando demonio: %v", err)
				} else {
					_ = cmd.Process.Release()
					failures = 0
					time.Sleep(4 * time.Second)
				}
			}
		}
		time.Sleep(*interval)
	}
}
