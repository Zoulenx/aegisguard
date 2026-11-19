package filter

import (
	"strings"
	"sync"
	"unicode"

	"aegisguard/windows/internal/rules"
)

type TextVerdict struct {
	Blocked      bool     `json:"blocked"`
	Warning      bool     `json:"warning"`
	Score        int      `json:"score"`
	MatchedTerms []string `json:"matched_terms"`
	Normalized   string   `json:"normalized"`
	Reason       string   `json:"reason"`
}

type SemanticFilter struct {
	mu                sync.RWMutex
	thresholdBlock    int
	thresholdWarn     int
	leetspeak         map[rune]rune
	highRiskWords     map[string]struct{}
	highRiskPhrases   []string
	mediumRiskWords   map[string]struct{}
	mediumRiskPhrases []string
	emojis            []string
	safeContexts      []string
	customBlocked     []string
}

func NewSemanticFilter(kr *rules.KeywordRules) *SemanticFilter {
	sf := &SemanticFilter{
		thresholdBlock:  kr.ThresholdBlock,
		thresholdWarn:   kr.ThresholdWarn,
		leetspeak:       make(map[rune]rune),
		highRiskWords:   make(map[string]struct{}),
		mediumRiskWords: make(map[string]struct{}),
		emojis:          append([]string(nil), kr.SuggestiveEmojiCombos...),
	}
	if sf.thresholdBlock <= 0 {
		sf.thresholdBlock = 100
	}
	if sf.thresholdWarn <= 0 {
		sf.thresholdWarn = 60
	}
	for k, v := range kr.LeetspeakMap {
		krune := []rune(k)
		vrune := []rune(v)
		if len(krune) == 1 && len(vrune) == 1 {
			sf.leetspeak[krune[0]] = vrune[0]
		}
	}
	for _, t := range kr.ExactHighRiskTerms {
		norm := sf.normalizeTerm(t)
		if norm == "" {
			continue
		}
		if strings.Contains(norm, " ") || strings.HasPrefix(t, "+") {
			sf.highRiskPhrases = append(sf.highRiskPhrases, norm)
		} else {
			sf.highRiskWords[norm] = struct{}{}
		}
	}
	for _, t := range kr.ContextMediumRiskTerm {
		norm := sf.normalizeTerm(t)
		if norm == "" {
			continue
		}
		if strings.Contains(norm, " ") {
			sf.mediumRiskPhrases = append(sf.mediumRiskPhrases, norm)
		} else {
			sf.mediumRiskWords[norm] = struct{}{}
		}
	}
	for _, w := range kr.SafeWhitelistContexts {
		norm := sf.normalizeTerm(w)
		if norm != "" {
			sf.safeContexts = append(sf.safeContexts, norm)
		}
	}
	return sf
}

func (sf *SemanticFilter) AddCustomTerms(terms []string) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	for _, t := range terms {
		norm := sf.normalizeTerm(t)
		if norm == "" {
			continue
		}
		sf.customBlocked = append(sf.customBlocked, norm)
		if strings.Contains(norm, " ") {
			sf.highRiskPhrases = append(sf.highRiskPhrases, norm)
		} else {
			sf.highRiskWords[norm] = struct{}{}
		}
	}
}

func (sf *SemanticFilter) CustomTerms() []string {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	out := make([]string, len(sf.customBlocked))
	copy(out, sf.customBlocked)
	return out
}

// Analyze inspects text (searches, URLs, hashtags, social app inputs) with anti-obfuscation normalization.
func (sf *SemanticFilter) Analyze(input string) TextVerdict {
	sf.mu.RLock()
	defer sf.mu.RUnlock()

	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return TextVerdict{}
	}

	// Keep raw check for markers like "+18" or "18+"
	rawLower := strings.ToLower(trimmed)
	norm := sf.normalizeInput(trimmed)
	collapsed := collapseRepeats(norm)
	deSpaced := joinSingleLetterRuns(collapsed)

	// Safe whitelist check: mask out known educational/innocent phrases before scoring.
	cleaned := collapsed
	cleanedDeSpaced := deSpaced
	for _, safe := range sf.safeContexts {
		if strings.Contains(cleaned, safe) {
			cleaned = strings.ReplaceAll(cleaned, safe, " ")
		}
		if strings.Contains(cleanedDeSpaced, safe) {
			cleanedDeSpaced = strings.ReplaceAll(cleanedDeSpaced, safe, " ")
		}
	}

	score := 0
	matchedSet := make(map[string]struct{})
	addMatch := func(term string, points int) {
		if _, exists := matchedSet[term]; !exists {
			matchedSet[term] = struct{}{}
			score += points
		}
	}

	// Check explicit markers "+18" / "18+"
	if strings.Contains(rawLower, "+18") || strings.Contains(rawLower, "18+") {
		addMatch("+18", 55)
	}

	// 1. Check high-risk phrases across both cleaned and de-spaced variants
	for _, phrase := range sf.highRiskPhrases {
		if containsWordPhrase(cleaned, phrase) || containsWordPhrase(cleanedDeSpaced, phrase) {
			addMatch(phrase, 110)
		}
	}

	// 2. Token-level analysis (handles exact words, hashtags, and concatenated obfuscation)
	tokens := uniqueTokens(cleaned, cleanedDeSpaced)
	for _, tok := range tokens {
		if _, ok := sf.highRiskWords[tok]; ok {
			addMatch(tok, 105)
			continue
		}
		// Check compact leetspeak/obfuscation without punctuation (e.g., "p.o.r.n.o" -> "porno")
		if _, ok := sf.mediumRiskWords[tok]; ok {
			addMatch(tok, 45)
		}
	}

	// 3. Check medium-risk phrases
	for _, phrase := range sf.mediumRiskPhrases {
		if containsWordPhrase(cleaned, phrase) || containsWordPhrase(cleanedDeSpaced, phrase) {
			addMatch(phrase, 50)
		}
	}

	// 4. Compact check for glued high-risk words >= 5 chars (e.g., "verpornohd", "onlyfansgratis", "nudesfiltrados")
	compact := strings.ReplaceAll(cleanedDeSpaced, " ", "")
	for word := range sf.highRiskWords {
		if len(word) >= 5 && strings.Contains(compact, word) {
			addMatch(word, 105)
		}
	}

	// 5. Suggestive emoji combinations (2+ suggestive emojis or 1 emoji + medium risk term)
	emojiCount := 0
	for _, em := range sf.emojis {
		if strings.Contains(trimmed, em) {
			emojiCount++
		}
	}
	if emojiCount >= 3 {
		addMatch("emojis_explicitos", 105)
	} else if emojiCount >= 1 {
		addMatch("emoji_sugestivo", emojiCount*35)
	}

	matched := make([]string, 0, len(matchedSet))
	for m := range matchedSet {
		matched = append(matched, m)
	}

	verdict := TextVerdict{
		Score:        score,
		MatchedTerms: matched,
		Normalized:   cleanedDeSpaced,
	}
	if score >= sf.thresholdBlock {
		verdict.Blocked = true
		verdict.Reason = "Contenido o búsqueda explícita detectada (" + strings.Join(matched, ", ") + ")"
	} else if score >= sf.thresholdWarn {
		verdict.Warning = true
		verdict.Reason = "Contenido sugestivo detectado (" + strings.Join(matched, ", ") + ")"
	}
	return verdict
}

func (sf *SemanticFilter) normalizeTerm(s string) string {
	return collapseRepeats(sf.normalizeInput(s))
}

func (sf *SemanticFilter) normalizeInput(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false

	for _, r := range strings.ToLower(s) {
		// Strip zero-width & format characters used to bypass filters
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		// Map common Spanish/Latin diacritics to ASCII base
		r = stripDiacritic(r)
		// Map leetspeak symbols/digits
		if mapped, ok := sf.leetspeak[r]; ok {
			r = mapped
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevSpace = false
		} else {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func stripDiacritic(r rune) rune {
	switch r {
	case 'á', 'à', 'ä', 'â', 'ã', 'å':
		return 'a'
	case 'é', 'è', 'ë', 'ê':
		return 'e'
	case 'í', 'ì', 'ï', 'î':
		return 'i'
	case 'ó', 'ò', 'ö', 'ô', 'õ':
		return 'o'
	case 'ú', 'ù', 'ü', 'û':
		return 'u'
	case 'ñ':
		return 'n'
	case 'ç':
		return 'c'
	case 'ý', 'ÿ':
		return 'y'
	default:
		return r
	}
}

// collapseRepeats reduces 3+ consecutive identical letters (e.g. "pooooornooo" -> "porno", "sexxx" -> "sex").
// Special-case "xxx" so explicit "xxx" stays recognizable.
func collapseRepeats(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if w == "xxx" {
			continue
		}
		var b strings.Builder
		var last rune
		runLen := 0
		for _, r := range w {
			if r == last {
				runLen++
				// Allow max 1 repeat for letters like 'o'/'a' when runLen >= 2 -> collapse to 1 if >=3
				if runLen < 2 {
					b.WriteRune(r)
				}
			} else {
				last = r
				runLen = 1
				b.WriteRune(r)
			}
		}
		// Also collapse double-letter obfuscation when triple was written (e.g. "pooorno" -> "poorno" -> check single)
		res := b.String()
		if len(res) > 3 {
			res = collapseExcessivePairs(w, res)
		}
		words[i] = res
	}
	return strings.Join(words, " ")
}

func collapseExcessivePairs(orig, dedup string) string {
	// If original had any run >= 3, collapse all runs to length 1 to catch "pooooornooo" -> "porno"
	var last rune
	runLen := 0
	hasLongRun := false
	for _, r := range orig {
		if r == last {
			runLen++
			if runLen >= 3 {
				hasLongRun = true
				break
			}
		} else {
			last = r
			runLen = 1
		}
	}
	if !hasLongRun {
		return dedup
	}
	var b strings.Builder
	last = 0
	for _, r := range orig {
		if r != last {
			b.WriteRune(r)
			last = r
		}
	}
	return b.String()
}

// joinSingleLetterRuns turns spaced-out obfuscation like "p o r n o gratis" into "porno gratis".
func joinSingleLetterRuns(s string) string {
	parts := strings.Fields(s)
	if len(parts) < 3 {
		return s
	}
	var out []string
	var buf strings.Builder
	singleCount := 0

	flush := func() {
		if singleCount >= 3 {
			out = append(out, buf.String())
		} else if singleCount > 0 {
			for _, r := range buf.String() {
				out = append(out, string(r))
			}
		}
		buf.Reset()
		singleCount = 0
	}

	for _, p := range parts {
		if len([]rune(p)) == 1 {
			buf.WriteString(p)
			singleCount++
		} else {
			flush()
			out = append(out, p)
		}
	}
	flush()
	return strings.Join(out, " ")
}

func containsWordPhrase(haystack, phrase string) bool {
	if haystack == "" || phrase == "" {
		return false
	}
	paddedHaystack := " " + haystack + " "
	paddedPhrase := " " + phrase + " "
	return strings.Contains(paddedHaystack, paddedPhrase)
}

func uniqueTokens(a, b string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range []string{a, b} {
		for _, f := range strings.Fields(s) {
			if _, ok := seen[f]; !ok {
				seen[f] = struct{}{}
				out = append(out, f)
			}
		}
	}
	return out
}
