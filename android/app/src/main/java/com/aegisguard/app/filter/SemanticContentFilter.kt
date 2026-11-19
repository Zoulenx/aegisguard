package com.aegisguard.app.filter

import android.content.Context
import org.json.JSONObject
import java.text.Normalizer

data class TextVerdict(
    val blocked: Boolean = false,
    val warning: Boolean = false,
    val score: Int = 0,
    val matchedTerms: List<String> = emptyList(),
    val normalized: String = "",
    val reason: String = ""
)

/**
 * Motor semántico y anti-ofuscación multilingüe (ES/EN) 100% local en dispositivo.
 * Detecta palabras sexuales, leetspeak (p0rn0, s3x0), letras repetidas (pooooorno),
 * caracteres invisibles (zero-width), letras separadas (p o r n o) y combinaciones de emojis,
 * respetando contextos seguros (educación, biología, medicina).
 */
class SemanticContentFilter private constructor(
    private val thresholdBlock: Int,
    private val thresholdWarn: Int,
    private val leetspeak: Map<Char, Char>,
    private val highRiskWords: MutableSet<String>,
    private val highRiskPhrases: MutableList<String>,
    private val mediumRiskWords: Set<String>,
    private val mediumRiskPhrases: List<String>,
    private val emojis: List<String>,
    private val safeContexts: List<String>
) {

    @Synchronized
    fun addCustomTerms(terms: Collection<String>) {
        for (raw in terms) {
            val norm = normalizeTerm(raw)
            if (norm.isBlank()) continue
            if (norm.contains(' ')) highRiskPhrases.add(norm) else highRiskWords.add(norm)
        }
    }

    @Synchronized
    fun analyze(input: String): TextVerdict {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return TextVerdict()

        val rawLower = trimmed.lowercase()
        val norm = normalizeInput(trimmed)
        val collapsed = collapseRepeats(norm)
        val deSpaced = joinSingleLetterRuns(collapsed)

        var cleaned = collapsed
        var cleanedDeSpaced = deSpaced
        for (safe in safeContexts) {
            if (cleaned.contains(safe)) cleaned = cleaned.replace(safe, " ")
            if (cleanedDeSpaced.contains(safe)) cleanedDeSpaced = cleanedDeSpaced.replace(safe, " ")
        }

        var score = 0
        val matched = LinkedHashSet<String>()
        fun addMatch(term: String, points: Int) {
            if (matched.add(term)) score += points
        }

        if (rawLower.contains("+18") || rawLower.contains("18+")) {
            addMatch("+18", 55)
        }

        for (phrase in highRiskPhrases) {
            if (containsWordPhrase(cleaned, phrase) || containsWordPhrase(cleanedDeSpaced, phrase)) {
                addMatch(phrase, 110)
            }
        }

        val tokens = (cleaned.split(' ') + cleanedDeSpaced.split(' ')).filter { it.isNotBlank() }.toSet()
        for (tok in tokens) {
            when {
                highRiskWords.contains(tok) -> addMatch(tok, 105)
                mediumRiskWords.contains(tok) -> addMatch(tok, 45)
            }
        }

        for (phrase in mediumRiskPhrases) {
            if (containsWordPhrase(cleaned, phrase) || containsWordPhrase(cleanedDeSpaced, phrase)) {
                addMatch(phrase, 50)
            }
        }

        val compact = cleanedDeSpaced.replace(" ", "")
        for (word in highRiskWords) {
            if (word.length >= 5 && compact.contains(word)) {
                addMatch(word, 105)
            }
        }

        val emojiCount = emojis.count { trimmed.contains(it) }
        if (emojiCount >= 3) {
            addMatch("emojis_explicitos", 105)
        } else if (emojiCount >= 1) {
            addMatch("emoji_sugestivo", emojiCount * 35)
        }

        val list = matched.toList()
        return when {
            score >= thresholdBlock -> TextVerdict(
                blocked = true,
                score = score,
                matchedTerms = list,
                normalized = cleanedDeSpaced,
                reason = "Contenido o búsqueda explícita detectada (${list.joinToString(", ")})"
            )
            score >= thresholdWarn -> TextVerdict(
                warning = true,
                score = score,
                matchedTerms = list,
                normalized = cleanedDeSpaced,
                reason = "Contenido sugestivo detectado (${list.joinToString(", ")})"
            )
            else -> TextVerdict(score = score, matchedTerms = list, normalized = cleanedDeSpaced)
        }
    }

    private fun normalizeTerm(s: String): String = collapseRepeats(normalizeInput(s))

    private fun normalizeInput(s: String): String {
        val decomposed = Normalizer.normalize(s.lowercase(), Normalizer.Form.NFD)
        val sb = StringBuilder(decomposed.length)
        var prevSpace = false
        for (ch in decomposed) {
            val type = Character.getType(ch)
            if (type == Character.NON_SPACING_MARK.toInt() || type == Character.FORMAT.toInt()) continue
            val mapped = leetspeak[ch] ?: ch
            if (mapped.isLetterOrDigit()) {
                sb.append(mapped)
                prevSpace = false
            } else if (!prevSpace) {
                sb.append(' ')
                prevSpace = true
            }
        }
        return sb.toString().trim()
    }

    private fun collapseRepeats(s: String): String {
        return s.split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ") { w ->
            if (w == "xxx") return@joinToString w
            var hasTriple = false
            var last = '\u0000'
            var run = 0
            for (c in w) {
                if (c == last) {
                    run++
                    if (run >= 3) {
                        hasTriple = true
                        break
                    }
                } else {
                    last = c
                    run = 1
                }
            }
            if (!hasTriple) return@joinToString w
            val out = StringBuilder()
            last = '\u0000'
            for (c in w) {
                if (c != last) {
                    out.append(c)
                    last = c
                }
            }
            out.toString()
        }
    }

    private fun joinSingleLetterRuns(s: String): String {
        val parts = s.split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.size < 3) return s
        val out = ArrayList<String>(parts.size)
        val buf = StringBuilder()
        var count = 0

        fun flush() {
            if (count >= 3) {
                out.add(buf.toString())
            } else if (count > 0) {
                for (c in buf.toString()) out.add(c.toString())
            }
            buf.setLength(0)
            count = 0
        }

        for (p in parts) {
            if (p.length == 1) {
                buf.append(p)
                count++
            } else {
                flush()
                out.add(p)
            }
        }
        flush()
        return out.joinToString(" ")
    }

    private fun containsWordPhrase(haystack: String, phrase: String): Boolean {
        if (haystack.isEmpty() || phrase.isEmpty()) return false
        return " $haystack ".contains(" $phrase ")
    }

    companion object {
        @Volatile
        private var instance: SemanticContentFilter? = null

        fun getInstance(context: Context): SemanticContentFilter {
            return instance ?: synchronized(this) {
                instance ?: loadFromAssets(context.applicationContext).also { instance = it }
            }
        }

        fun loadFromAssets(context: Context): SemanticContentFilter {
            val raw = context.assets.open("explicit_keywords.json").bufferedReader().use { it.readText() }
            return fromJson(raw)
        }

        fun fromJson(rawJson: String): SemanticContentFilter {
            val obj = JSONObject(rawJson)
            val thresholdBlock = obj.optInt("threshold_block", 100)
            val thresholdWarn = obj.optInt("threshold_warn", 60)

            val leet = HashMap<Char, Char>()
            val leetObj = obj.optJSONObject("leetspeak_map")
            if (leetObj != null) {
                val keys = leetObj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    val v = leetObj.optString(k)
                    if (k.length == 1 && v.length == 1) leet[k[0]] = v[0]
                }
            }

            val sfTemp = SemanticContentFilter(
                thresholdBlock, thresholdWarn, leet,
                HashSet(), ArrayList(), HashSet(), ArrayList(), emptyList(), emptyList()
            )

            val highWords = HashSet<String>()
            val highPhrases = ArrayList<String>()
            val highArr = obj.optJSONArray("exact_high_risk_terms")
            if (highArr != null) {
                for (i in 0 until highArr.length()) {
                    val orig = highArr.optString(i)
                    val norm = sfTemp.normalizeTerm(orig)
                    if (norm.isEmpty()) continue
                    if (norm.contains(' ') || orig.startsWith("+")) highPhrases.add(norm) else highWords.add(norm)
                }
            }

            val medWords = HashSet<String>()
            val medPhrases = ArrayList<String>()
            val medArr = obj.optJSONArray("context_medium_risk_terms")
            if (medArr != null) {
                for (i in 0 until medArr.length()) {
                    val norm = sfTemp.normalizeTerm(medArr.optString(i))
                    if (norm.isEmpty()) continue
                    if (norm.contains(' ')) medPhrases.add(norm) else medWords.add(norm)
                }
            }

            val emojis = ArrayList<String>()
            val emArr = obj.optJSONArray("suggestive_emoji_combos")
            if (emArr != null) {
                for (i in 0 until emArr.length()) emojis.add(emArr.optString(i))
            }

            val safe = ArrayList<String>()
            val safeArr = obj.optJSONArray("safe_whitelist_contexts")
            if (safeArr != null) {
                for (i in 0 until safeArr.length()) {
                    val norm = sfTemp.normalizeTerm(safeArr.optString(i))
                    if (norm.isNotEmpty()) safe.add(norm)
                }
            }

            return SemanticContentFilter(
                thresholdBlock, thresholdWarn, leet,
                highWords, highPhrases, medWords, medPhrases, emojis, safe
            )
        }
    }
}
