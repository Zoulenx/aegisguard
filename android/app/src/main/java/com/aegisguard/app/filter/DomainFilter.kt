package com.aegisguard.app.filter

import android.content.Context
import org.json.JSONObject

data class DomainDecision(
    val action: String, // "ALLOW", "BLOCK", "SAFESEARCH"
    val reason: String = "",
    val safeSearchHost: String = ""
)

data class SocialAppSignature(
    val id: String,
    val name: String,
    val androidPackages: Set<String>,
    val webDomains: Set<String>,
    val triggerTabs: Set<String>
)

class DomainFilter private constructor(
    private val exactDomains: MutableSet<String>,
    private val blockedTLDs: MutableList<String>,
    private val socialDomains: Map<String, String>,
    private val safeSearchRewrites: Map<String, String>,
    val socialApps: List<SocialAppSignature>,
    private val semantic: SemanticContentFilter
) {
    @Volatile
    var socialBlockProvider: (() -> Pair<Boolean, String>)? = null

    private val packageToSocialApp: Map<String, SocialAppSignature> = buildMap {
        for (app in socialApps) {
            for (pkg in app.androidPackages) put(pkg, app)
        }
    }

    fun getSocialAppForPackage(packageName: String): SocialAppSignature? = packageToSocialApp[packageName]

    @Synchronized
    fun addCustomDomain(raw: String) {
        val d = cleanDomain(raw)
        if (d.isEmpty()) return
        if (d.startsWith(".")) blockedTLDs.add(d) else exactDomains.add(d)
    }

    @Synchronized
    fun evaluate(rawHost: String): DomainDecision {
        val host = cleanDomain(rawHost)
        if (host.isEmpty()) return DomainDecision("ALLOW")

        for (tld in blockedTLDs) {
            if (host.endsWith(tld)) {
                return DomainDecision("BLOCK", "Dominio con TLD explícito ($tld)")
            }
        }

        val parts = host.split('.')
        for (i in parts.indices) {
            val candidate = parts.subList(i, parts.size).joinToString(".")
            if (exactDomains.contains(candidate)) {
                return DomainDecision("BLOCK", "Dominio bloqueado ($candidate)")
            }
        }

        val labelText = parts.dropLast(1).ifEmpty { parts }.joinToString(" ").replace('-', ' ')
        val verdict = semantic.analyze(labelText)
        if (verdict.blocked) {
            return DomainDecision("BLOCK", "Heurística de dominio explícito: ${verdict.reason}")
        }

        val hook = socialBlockProvider
        if (hook != null) {
            val (blockSocial, reason) = hook()
            if (blockSocial) {
                for (i in parts.indices) {
                    val candidate = parts.subList(i, parts.size).joinToString(".")
                    val appId = socialDomains[candidate]
                    if (appId != null) {
                        return DomainDecision("BLOCK", "$reason (Red social: $appId)")
                    }
                }
            }
        }

        val safeTarget = safeSearchRewrites[host]
        if (safeTarget != null) {
            return DomainDecision("SAFESEARCH", "SafeSearch forzado -> $safeTarget", safeTarget)
        }

        return DomainDecision("ALLOW")
    }

    companion object {
        @Volatile
        private var instance: DomainFilter? = null

        fun getInstance(context: Context): DomainFilter {
            return instance ?: synchronized(this) {
                instance ?: loadFromAssets(context.applicationContext).also { instance = it }
            }
        }

        private fun cleanDomain(raw: String): String =
            raw.trim().lowercase().removeSuffix(".")

        private fun loadFromAssets(context: Context): DomainFilter {
            val semantic = SemanticContentFilter.getInstance(context)
            val exact = HashSet<String>()
            val tlds = ArrayList<String>()

            context.assets.open("blocklist_domains.txt").bufferedReader().useLines { lines ->
                for (raw in lines) {
                    val line = cleanDomain(raw)
                    if (line.isEmpty() || line.startsWith("#")) continue
                    if (line.startsWith(".")) tlds.add(line) else exact.add(line)
                }
            }

            val socialRaw = context.assets.open("social_apps.json").bufferedReader().use { it.readText() }
            val socialObj = JSONObject(socialRaw)
            val socialDomains = HashMap<String, String>()
            val apps = ArrayList<SocialAppSignature>()

            val appsArr = socialObj.optJSONArray("social_apps")
            if (appsArr != null) {
                for (i in 0 until appsArr.length()) {
                    val a = appsArr.getJSONObject(i)
                    val id = a.optString("id")
                    val name = a.optString("name")
                    val pkgs = HashSet<String>()
                    val doms = HashSet<String>()
                    val tabs = HashSet<String>()

                    a.optJSONArray("android_packages")?.let { arr ->
                        for (j in 0 until arr.length()) pkgs.add(arr.optString(j))
                    }
                    a.optJSONArray("web_domains")?.let { arr ->
                        for (j in 0 until arr.length()) {
                            val d = cleanDomain(arr.optString(j))
                            doms.add(d)
                            socialDomains[d] = id
                        }
                    }
                    a.optJSONArray("trigger_tabs")?.let { arr ->
                        for (j in 0 until arr.length()) tabs.add(arr.optString(j).lowercase())
                    }
                    apps.add(SocialAppSignature(id, name, pkgs, doms, tabs))
                }
            }

            val safeMap = HashMap<String, String>()
            val safeObj = socialObj.optJSONObject("safesearch_rewrites")
            if (safeObj != null) {
                val keys = safeObj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    safeMap[cleanDomain(k)] = cleanDomain(safeObj.optString(k))
                }
            }

            return DomainFilter(exact, tlds, socialDomains, safeMap, apps, semantic)
        }
    }
}
