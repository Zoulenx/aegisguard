package filter

import (
	"strings"
	"sync"

	"aegisguard/windows/internal/rules"
)

type DomainDecision struct {
	Action         string `json:"action"` // "ALLOW", "BLOCK", "SAFESEARCH"
	Reason         string `json:"reason"`
	SafeSearchHost string `json:"safesearch_host,omitempty"`
}

type DomainFilter struct {
	mu                 sync.RWMutex
	exactDomains       map[string]struct{}
	blockedTLDs        []string
	socialDomains      map[string]string // domain -> social app ID
	safeSearchRewrites map[string]string
	customDomains      []string
	blockSocialNow     func() (bool, string)
	semantic           *SemanticFilter
}

func NewDomainFilter(blocklist []string, socialRules *rules.SocialAppRules, sf *SemanticFilter) *DomainFilter {
	df := &DomainFilter{
		exactDomains:       make(map[string]struct{}, len(blocklist)),
		socialDomains:      make(map[string]string),
		safeSearchRewrites: make(map[string]string),
		semantic:           sf,
	}
	for _, d := range blocklist {
		d = cleanDomain(d)
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, ".") {
			df.blockedTLDs = append(df.blockedTLDs, d)
		} else {
			df.exactDomains[d] = struct{}{}
		}
	}
	if socialRules != nil {
		for _, app := range socialRules.SocialApps {
			for _, dom := range app.WebDomains {
				df.socialDomains[cleanDomain(dom)] = app.ID
			}
		}
		for k, v := range socialRules.SafeSearchRewrites {
			df.safeSearchRewrites[cleanDomain(k)] = cleanDomain(v)
		}
	}
	return df
}

func (df *DomainFilter) SetSocialBlockHook(fn func() (bool, string)) {
	df.mu.Lock()
	defer df.mu.Unlock()
	df.blockSocialNow = fn
}

func (df *DomainFilter) AddCustomDomain(domain string) {
	d := cleanDomain(domain)
	if d == "" {
		return
	}
	df.mu.Lock()
	defer df.mu.Unlock()
	df.customDomains = append(df.customDomains, d)
	if strings.HasPrefix(d, ".") {
		df.blockedTLDs = append(df.blockedTLDs, d)
	} else {
		df.exactDomains[d] = struct{}{}
	}
}

func (df *DomainFilter) CustomDomains() []string {
	df.mu.RLock()
	defer df.mu.RUnlock()
	out := make([]string, len(df.customDomains))
	copy(out, df.customDomains)
	return out
}

func (df *DomainFilter) BlockedDomainsList() []string {
	df.mu.RLock()
	defer df.mu.RUnlock()
	out := make([]string, 0, len(df.exactDomains))
	for d := range df.exactDomains {
		out = append(out, d)
	}
	return out
}

func (df *DomainFilter) Evaluate(rawHost string) DomainDecision {
	host := cleanDomain(rawHost)
	if host == "" {
		return DomainDecision{Action: "ALLOW"}
	}

	df.mu.RLock()
	defer df.mu.RUnlock()

	// 1. Check explicit TLDs (.xxx, .porn, .sex, .adult, etc.)
	for _, tld := range df.blockedTLDs {
		if strings.HasSuffix(host, tld) {
			return DomainDecision{Action: "BLOCK", Reason: "Dominio con TLD explícito (" + tld + ")"}
		}
	}

	// 2. Exact & parent domain match (e.g., es.pornhub.com matches pornhub.com)
	parts := strings.Split(host, ".")
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		if _, blocked := df.exactDomains[candidate]; blocked {
			return DomainDecision{Action: "BLOCK", Reason: "Dominio en lista de bloqueo (" + candidate + ")"}
		}
	}

	// 3. Heuristic domain name check using semantic filter on SLD/subdomains
	if df.semantic != nil {
		labelText := strings.ReplaceAll(strings.Join(parts[:maxInt(1, len(parts)-1)], " "), "-", " ")
		verdict := df.semantic.Analyze(labelText)
		if verdict.Blocked {
			return DomainDecision{Action: "BLOCK", Reason: "Heurística de dominio explícito: " + verdict.Reason}
		}
	}

	// 4. Social media temporary lockdown (Panic Mode or Night Risk Schedule)
	if df.blockSocialNow != nil {
		if blockSocial, reason := df.blockSocialNow(); blockSocial {
			for i := 0; i < len(parts); i++ {
				candidate := strings.Join(parts[i:], ".")
				if appID, isSocial := df.socialDomains[candidate]; isSocial {
					return DomainDecision{Action: "BLOCK", Reason: reason + " (Red social: " + appID + ")"}
				}
			}
		}
	}

	// 5. SafeSearch enforcement for major search engines & YouTube
	if target, ok := df.safeSearchRewrites[host]; ok {
		return DomainDecision{
			Action:         "SAFESEARCH",
			Reason:         "Búsqueda segura forzada -> " + target,
			SafeSearchHost: target,
		}
	}

	return DomainDecision{Action: "ALLOW"}
}

func cleanDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	return d
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
