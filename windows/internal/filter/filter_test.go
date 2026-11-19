package filter

import (
	"testing"

	"aegisguard/windows/internal/rules"
)

func TestSemanticFilterDetectsObfuscationAndAvoidsFalsePositives(t *testing.T) {
	kr, err := rules.LoadEmbeddedKeywords()
	if err != nil {
		t.Fatalf("failed loading keywords: %v", err)
	}
	sf := NewSemanticFilter(kr)

	shouldBlock := []string{
		"videos porno gratis",
		"p0rn0 hd",
		"p o r n o",
		"pooooornoooo",
		"s3x0 sin censura",
		"chicas d3snud4s instagram",
		"nudes filtrados onlyfans",
		"buscando pack telegram 🍑💦🍆",
		"verhentaiuncensored",
		"pagina azul link en bio +18",
		"chica caliente sin ropa",
		"p\u200bo\u200br\u200bn\u200bh\u200bu\u200bb",
	}
	for _, tc := range shouldBlock {
		v := sf.Analyze(tc)
		if !v.Blocked {
			t.Errorf("expected BLOCK for %q, got score=%d matched=%v norm=%q", tc, v.Score, v.MatchedTerms, v.Normalized)
		}
	}

	shouldAllow := []string{
		"receta de pasta italiana",
		"analisis de datos con python",
		"educacion sexual para adolescentes wikipedia",
		"como arreglar mi computadora windows",
		"hot dog receta casera",
		"pack de iconos gratis para diseño",
		"ford escort 1998 manual",
		"noticias de futbol hoy",
	}
	for _, tc := range shouldAllow {
		v := sf.Analyze(tc)
		if v.Blocked {
			t.Errorf("expected ALLOW for %q, got BLOCK score=%d matched=%v", tc, v.Score, v.MatchedTerms)
		}
	}
}

func TestDomainFilterBlocksAdultDoHAndEnforcesSafeSearch(t *testing.T) {
	domains, err := rules.LoadEmbeddedBlocklist()
	if err != nil {
		t.Fatalf("failed loading blocklist: %v", err)
	}
	kr, _ := rules.LoadEmbeddedKeywords()
	sr, _ := rules.LoadEmbeddedSocialApps()
	sf := NewSemanticFilter(kr)
	df := NewDomainFilter(domains, sr, sf)

	// Direct & subdomain adult sites
	for _, host := range []string{
		"pornhub.com",
		"es.pornhub.com",
		"m.xvideos.com",
		"site-random.xxx",
		"super-porno-nuevo-2026.com",
		"dns.google",
		"croxyproxy.com",
	} {
		dec := df.Evaluate(host)
		if dec.Action != "BLOCK" {
			t.Errorf("expected BLOCK for %q, got %+v", host, dec)
		}
	}

	// SafeSearch rewrite
	dec := df.Evaluate("www.google.com")
	if dec.Action != "SAFESEARCH" || dec.SafeSearchHost != "forcesafesearch.google.com" {
		t.Errorf("expected SAFESEARCH for www.google.com, got %+v", dec)
	}

	// Normal site allowed
	dec = df.Evaluate("wikipedia.org")
	if dec.Action != "ALLOW" {
		t.Errorf("expected ALLOW for wikipedia.org, got %+v", dec)
	}

	// Social media lockdown hook
	df.SetSocialBlockHook(func() (bool, string) {
		return true, "Modo Pánico activo"
	})
	dec = df.Evaluate("www.instagram.com")
	if dec.Action != "BLOCK" {
		t.Errorf("expected BLOCK for instagram during panic mode, got %+v", dec)
	}
}
