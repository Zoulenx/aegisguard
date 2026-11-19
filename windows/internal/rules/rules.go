package rules

import (
	"embed"
	"encoding/json"
	"strings"
)

//go:embed assets/blocklist_domains.txt assets/explicit_keywords.json assets/social_apps.json
var embeddedFS embed.FS

type KeywordRules struct {
	Version               string            `json:"version"`
	ThresholdBlock        int               `json:"threshold_block"`
	ThresholdWarn         int               `json:"threshold_warn"`
	LeetspeakMap          map[string]string `json:"leetspeak_map"`
	ExactHighRiskTerms    []string          `json:"exact_high_risk_terms"`
	ContextMediumRiskTerm []string          `json:"context_medium_risk_terms"`
	SuggestiveEmojiCombos []string          `json:"suggestive_emoji_combos"`
	SafeWhitelistContexts []string          `json:"safe_whitelist_contexts"`
}

type SocialAppRule struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	AndroidPackages  []string `json:"android_packages"`
	WindowsProcesses []string `json:"windows_processes"`
	WebDomains       []string `json:"web_domains"`
	TriggerTabs      []string `json:"trigger_tabs"`
	TriggerURLPaths  []string `json:"trigger_url_paths"`
}

type SocialAppRules struct {
	Version            string            `json:"version"`
	SocialApps         []SocialAppRule   `json:"social_apps"`
	SafeSearchRewrites map[string]string `json:"safesearch_rewrites"`
}

func LoadEmbeddedBlocklist() ([]string, error) {
	data, err := embeddedFS.ReadFile("assets/blocklist_domains.txt")
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, strings.ToLower(line))
	}
	return domains, nil
}

func LoadEmbeddedKeywords() (*KeywordRules, error) {
	data, err := embeddedFS.ReadFile("assets/explicit_keywords.json")
	if err != nil {
		return nil, err
	}
	var kr KeywordRules
	if err := json.Unmarshal(data, &kr); err != nil {
		return nil, err
	}
	return &kr, nil
}

func LoadEmbeddedSocialApps() (*SocialAppRules, error) {
	data, err := embeddedFS.ReadFile("assets/social_apps.json")
	if err != nil {
		return nil, err
	}
	var sr SocialAppRules
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, err
	}
	return &sr, nil
}
