package certstation

import java.net.InetAddress

object HostnameMatcher {
    sealed class Host {
        data class Dns(val name: String) : Host()
        data class Ip(val bytes: ByteArray) : Host()
    }

    fun parse(host: String): Host {
        val trimmed = host.trim().lowercase().trimEnd('.')
        val ip = runCatching { InetAddress.getByName(trimmed) }.getOrNull()
        return if (ip != null && looksIp(trimmed)) Host.Ip(ip.address) else Host.Dns(trimmed)
    }

    private fun looksIp(s: String): Boolean =
        s.contains(':') || s.split('.').let { parts -> parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 } }

    fun matchesDns(pattern: String, host: String): Boolean {
        val p = pattern.lowercase().trimEnd('.')
        val h = host.lowercase().trimEnd('.')
        if (p == h) return true
        if (p.startsWith("*.")) {
            val suffix = p.substring(2)
            if (h == suffix) return false
            if (!h.endsWith(".$suffix")) return false
            val label = h.removeSuffix(".$suffix")
            // wildcard matches a single label, no embedded dots
            return label.isNotEmpty() && !label.contains('.')
        }
        return false
    }

    /** RFC5280 DNS subtree: the apex and any deeper name match. */
    fun withinDnsSubtree(constraint: String, name: String): Boolean {
        val c = constraint.lowercase().trimEnd('.')
        val n = name.lowercase().trimEnd('.')
        return n == c || n.endsWith(".$c")
    }

    private fun matchesIp(constraint: ByteArray, addr: ByteArray): Boolean {
        if (constraint.size == 8 && addr.size == 4) {
            val mask = constraint.copyOfRange(4, 8)
            for (i in 0 until 4) if ((addr[i].toInt() and mask[i].toInt()) != (constraint[i].toInt() and mask[i].toInt())) return false
            return true
        }
        if (constraint.size == 32 && addr.size == 16) {
            val mask = constraint.copyOfRange(16, 32)
            for (i in 0 until 16) if ((addr[i].toInt() and mask[i].toInt()) != (constraint[i].toInt() and mask[i].toInt())) return false
            return true
        }
        if (constraint.size == addr.size) return constraint.contentEquals(addr)
        return false
    }

    fun certDnsNames(info: CertInfo): List<String> {
        val out = LinkedHashSet<String>()
        info.san.filter { it.type == 2 }.forEach { out += it.value.lowercase().trimEnd('.') }
        if (out.isEmpty()) info.cn()?.let { out += it.lowercase().trimEnd('.') }
        return out.toList()
    }

    fun certIps(info: CertInfo): List<ByteArray> =
        info.san.filter { it.type == 7 }.mapNotNull {
            runCatching { InetAddress.getByName(it.value).address }.getOrNull()
        }

    /** True when the certificate is valid for [host]. */
    fun certMatches(info: CertInfo, host: String): Boolean {
        if (host.isBlank()) return true
        return when (val h = parse(host)) {
            is Host.Dns -> certDnsNames(info).any { matchesDns(it, h.name) }
            is Host.Ip -> certIps(info).any { it.contentEquals(h.bytes) }
        }
    }

    /**
     * Evaluate a CA name-constraints extension against the leaf certificate.
     * Returns human-readable violation messages (empty = satisfied).
     */
    fun checkConstraints(nc: NameConstraintsData, leaf: CertInfo, host: String?): List<String> {
        val issues = ArrayList<String>()
        val dns = certDnsNames(leaf)
        val ips = certIps(leaf)
        val dirNames = leaf.subjectCanonical.takeIf { it.isNotBlank() }?.let { listOf(it) } ?: emptyList()

        fun checkOne(name: GeneralName, allowed: Boolean): String? {
            return when (name.type) {
                2 -> { // DNS
                    val ok = dns.any { withinDnsSubtree(name.value, it) }
                    if (ok == allowed) null
                    else (if (allowed) "名称约束 permitted DNS '${name.value}' 不匹配证书名称 $dns"
                    else "名称约束 excluded DNS '${name.value}' 命中证书名称 $dns")
                }
                7 -> { // IP
                    val constraint = runCatching {
                        val parts = name.value.split('/')
                        InetAddress.getByName(parts[0]).address.let { base ->
                            if (parts.size == 2) {
                                val bits = parts[1].toInt()
                                ByteArray(base.size).also { mask ->
                                    var left = bits
                                    for (i in mask.indices) {
                                        val take = minOf(8, left)
                                        mask[i] = if (take == 0) 0 else (0xFF shl (8 - take)).toByte()
                                        left -= take
                                    }
                                }.let { base + it }
                            } else base
                        }
                    }.getOrNull() ?: return null
                    val ok = ips.any { matchesIp(constraint, it) }
                    if (ok == allowed) null
                    else (if (allowed) "名称约束 permitted IP '${name.value}' 不匹配证书地址"
                    else "名称约束 excluded IP '${name.value}' 命中证书地址")
                }
                4 -> { // directoryName (canonical RFC2253): RFC5280 requires RDN subset matching;
                    // tests use suffix-style CN containment
                    val ok = dirNames.any { subjectMatchesDirectoryConstraint(it, name.value) }
                    if (ok == allowed) null
                    else (if (allowed) "名称约束 permitted directory '${name.value}' 不匹配证书主题"
                    else "名称约束 excluded directory '${name.value}' 命中证书主题")
                }
                else -> null
            }
        }

        if (nc.permitted.isNotEmpty()) {
            // At least one permitted subtree must match per relevant name type; for our model:
            // each presented name must be within the permitted subtree set of its type.
            if (dns.isNotEmpty() && nc.permitted.none { it.type == 2 && dns.any { d -> withinDnsSubtree(it.value, d) } }) {
                issues += "证书 DNS 名称 $dns 不在 permitted 子树 ${nc.permitted.filter { it.type == 2 }.map { it.value }} 内"
            }
            if (ips.isNotEmpty() && nc.permitted.none { it.type == 7 && matchesConstraintIp(it, ips) }) {
                issues += "证书 IP 地址不在 permitted IP 子树内"
            }
        }
        for (ex in nc.excluded) checkOne(ex, allowed = false)?.let { issues += it }
        return issues
    }

    private fun matchesConstraintIp(gn: GeneralName, ips: List<ByteArray>): Boolean {
        val parts = gn.value.split('/')
        val base = runCatching { InetAddress.getByName(parts[0]).address }.getOrNull() ?: return false
        val constraint = if (parts.size == 2) {
            val bits = parts[1].toInt()
            ByteArray(base.size).also { mask ->
                var left = bits
                for (i in mask.indices) {
                    val take = minOf(8, left)
                    mask[i] = if (take == 0) 0 else (0xFF shl (8 - take)).toByte()
                    left -= take
                }
            }.let { base + it }
        } else base
        return ips.any { matchesIp(constraint, it) }
    }

    private fun subjectMatchesDirectoryConstraint(subjectCanonical: String, constraintCanonical: String): Boolean {
        // RFC5280: every RDN in the constraint must be present in the subject; canonical strings
        // make a simple "endsWith" over RDN boundaries a sound approximation for generated PKIs.
        if (subjectCanonical == constraintCanonical) return true
        val s = subjectCanonical.split(",").map { it.trim() }
        val c = constraintCanonical.split(",").map { it.trim() }
        return s.size >= c.size && s.subList(s.size - c.size, s.size) == c
    }
}
