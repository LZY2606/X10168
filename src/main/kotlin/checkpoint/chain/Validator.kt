package checkpoint.chain

import checkpoint.model.CertInfo
import checkpoint.model.NameConstraint
import checkpoint.model.PolicyVersion
import java.time.Instant

data class CertFinding(
    val code: String,
    val severity: String,   // error / info
    val message: String
)

data class EvaluatedCert(
    val cert: CertInfo,
    val index: Int,
    val isAnchor: Boolean,
    val findings: List<CertFinding>,
    val signedBy: String?   // 下级证书对此证书的签名校验结果：ok / bad / null(无下级)
) {
    val errors: List<CertFinding> get() = findings.filter { it.severity == "error" }
}

data class EvaluatedChain(
    val order: List<CertInfo>,            // leaf -> anchor
    val anchor: CertInfo?,
    val terminal: String,
    val anchorPriority: Int?,
    val certs: List<EvaluatedCert>,
    val accepted: Boolean,
    val rejectReasons: List<String>
) {
    fun fingerprint(): String = order.joinToString("|") { it.fingerprintSha256.take(16) }
}

object Eku {
    const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
    const val CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    const val CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
    const val EMAIL = "1.3.6.1.5.5.7.3.4"

    fun oid(purpose: String): String = when (purpose.trim().lowercase()) {
        "serverauth", "server", "tls-server", "https" -> SERVER_AUTH
        "clientauth", "client", "tls-client" -> CLIENT_AUTH
        "codesigning", "code-signing" -> CODE_SIGNING
        "email", "smime" -> EMAIL
        else -> purpose.trim()
    }

    fun label(oid: String): String = when (oid) {
        SERVER_AUTH -> "serverAuth"
        CLIENT_AUTH -> "clientAuth"
        CODE_SIGNING -> "codeSigning"
        EMAIL -> "emailProtection"
        else -> oid
    }
}

class ChainValidator(
    private val at: Instant,
    private val policy: PolicyVersion,
    private val hostname: String?,
    private val purpose: String?
) {
    fun evaluate(raw: RawChain): EvaluatedChain {
        val order = raw.certs // leaf -> anchor
        val evaluated = mutableListOf<EvaluatedCert>()
        val globalReasons = mutableListOf<String>()

        if (raw.terminal != "none") {
            when (raw.terminal) {
                "anchor_unreachable" -> globalReasons += "CHAIN_ANCHOR_UNREACHABLE"
                "cycle" -> globalReasons += "CHAIN_CYCLE"
                "max_depth" -> globalReasons += "CHAIN_MAX_DEPTH"
            }
        }

        order.forEachIndexed { index, cert ->
            val isAnchor = raw.anchor?.fingerprintSha256 == cert.fingerprintSha256 &&
                index == order.size - 1
            val findings = mutableListOf<CertFinding>()
            checkTime(cert, findings)
            checkBasicConstraints(cert, index, order.size, isAnchor, findings)
            checkKeyUsage(cert, isAnchor, index, findings)
            checkEku(cert, isAnchor, index, findings)
            checkAlgorithmPolicy(cert, findings)
            if (index == 0) checkHostname(cert, findings)
            evaluated += EvaluatedCert(cert, index, isAnchor, findings, null)
        }

        // 签名：每个证书由其上级签名验证
        val byIndex = evaluated.associateBy { it.index }.toMutableMap()
        for (index in 0 until order.size - 1) {
            val child = order[index]
            val issuer = order[index + 1]
            val sigOk = verifySignature(child, issuer)
            val findings = byIndex.getValue(index).findings.toMutableList()
            if (sigOk) {
                findings += CertFinding("SIGNATURE_OK", "info", "签名由上级 ${issuer.labeledName()} 验证通过")
            } else {
                findings += CertFinding(
                    "SIGNATURE_INVALID", "error",
                    "签名验证失败：签发者 ${issuer.labeledName()} 的公钥无法验证此证书"
                )
            }
            byIndex[index] = evaluated[index].copy(findings = findings, signedBy = if (sigOk) "ok" else "bad")
        }
        raw.anchor?.let { anchor ->
            val findings = byIndex.getValue(order.size - 1).findings.toMutableList()
            findings += CertFinding("TRUST_ANCHOR", "info", "显式提供的 trust anchor（策略版本 ${policy.version}）")
            byIndex[order.size - 1] = evaluated.last().copy(findings = findings, signedBy = "anchor")
        }

        // path length：从 anchor 向下
        checkPathLengths(order, byIndex)
        // 名称约束：从 anchor 向下累积
        checkNameConstraints(order, byIndex)

        val finalCerts = order.indices.map { byIndex.getValue(it) }
        val certErrors = finalCerts.flatMap { ec ->
            ec.errors.map { "${ec.cert.labeledName()} :: ${it.code}" }
        }
        val accepted = raw.terminal == "none" && certErrors.isEmpty()
        return EvaluatedChain(
            order = order,
            anchor = raw.anchor,
            terminal = raw.terminal,
            anchorPriority = raw.anchorPriority,
            certs = finalCerts,
            accepted = accepted,
            rejectReasons = globalReasons + certErrors
        )
    }

    private fun verifySignature(child: CertInfo, issuer: CertInfo): Boolean =
        runCatching { child.x509.verify(issuer.x509.publicKey); true }.getOrDefault(false)

    private fun checkTime(cert: CertInfo, findings: MutableList<CertFinding>) {
        when {
            at.isBefore(cert.notBefore) -> findings += CertFinding(
                "NOT_YET_VALID", "error",
                "尚未生效：notBefore=${cert.notBefore}，验证时刻=$at（UTC，notBefore 当日 00:00 起可用）"
            )
            !at.isBefore(cert.notAfter) -> findings += CertFinding(
                "EXPIRED", "error",
                "已过期：notAfter=${cert.notAfter}，验证时刻=$at（UTC，恰好等于 notAfter 即过期）"
            )
            else -> findings += CertFinding("TIME_VALID", "info",
                "时间有效：${cert.notBefore} <= $at < ${cert.notAfter}（UTC；等于 notBefore 可用，等于 notAfter 过期）")
        }
    }

    private fun checkBasicConstraints(
        cert: CertInfo,
        index: Int,
        chainSize: Int,
        isAnchor: Boolean,
        findings: MutableList<CertFinding>
    ) {
        val mustBeCa = isAnchor || index > 0 // 除叶子（index=0）外都必须是 CA
        if (mustBeCa) {
            when {
                !cert.basicConstraintsPresent -> findings += CertFinding(
                    "BASIC_CONSTRAINTS_MISSING", "error",
                    "该证书位于链中（需作为 CA），但缺少 basicConstraints 扩展"
                )
                !cert.isCa -> findings += CertFinding(
                    "NOT_CA", "error",
                    "basicConstraints.cA=false，但该证书必须作为 CA 给下级发证"
                )
                else -> findings += CertFinding("BASIC_CONSTRAINTS_OK", "info",
                    "basicConstraints: cA=true" +
                        (cert.pathLenConstraint?.let { ", pathLenConstraint=$it" } ?: ""))
            }
        } else {
            if (cert.isCa) {
                findings += CertFinding("LEAF_IS_CA", "error",
                    "末端实体证书 basicConstraints.cA=true，不能作为叶子证书")
            } else {
                findings += CertFinding(
                    "BASIC_CONSTRAINTS_OK", "info",
                    if (cert.basicConstraintsPresent) "末端实体证书（cA=false）"
                    else "末端实体证书（无 basicConstraints）"
                )
            }
        }
    }

    private fun checkPathLengths(order: List<CertInfo>, byIndex: MutableMap<Int, EvaluatedCert>) {
        if (order.size < 3) return
        // anchor 是最后一个；中间 CA 是 1..size-2
        for (caIndex in 1 until order.size - 1) {
            val ca = order[caIndex]
            val limit = ca.pathLenConstraint ?: continue
            // 此 CA 之下、叶子之上的非自签中间 CA 数量
            val intermediateBelow = (0 until caIndex).count { idx ->
                val c = order[idx]
                idx > 0 && c.isCa && c.subjectDn != c.issuerDn
            }
            val findings = byIndex.getValue(caIndex).findings.toMutableList()
            if (intermediateBelow > limit) {
                findings += CertFinding("PATH_LENGTH_EXCEEDED", "error",
                    "pathLenConstraint=$limit，但该 CA 之下有 $intermediateBelow 个中间 CA")
            } else {
                findings += CertFinding("PATH_LENGTH_OK", "info",
                    "pathLenConstraint=$limit，之下中间 CA 数=$intermediateBelow")
            }
            byIndex[caIndex] = byIndex.getValue(caIndex).copy(findings = findings)
        }
    }

    private fun checkKeyUsage(
        cert: CertInfo,
        isAnchor: Boolean,
        index: Int,
        findings: MutableList<CertFinding>
    ) {
        val ku = cert.keyUsage ?: run {
            if (isAnchor) findings += CertFinding("KEY_USAGE_INFO", "info", "trust anchor 无 keyUsage 扩展（按锚点豁免强制要求）")
            return
        }
        val isLeaf = index == 0 && !isAnchor
        if (cert.isCa && !isLeaf) {
            if (!ku[5]) {
                findings += CertFinding("KEY_USAGE_NO_CERT_SIGN", "error",
                    "CA 证书 keyUsage 缺少 keyCertSign(bit5)")
            } else {
                findings += CertFinding("KEY_USAGE_OK", "info", "keyUsage 含 keyCertSign")
            }
        } else if (purpose != null) {
            val p = Eku.oid(purpose)
            if (p == Eku.SERVER_AUTH) {
                if (!(ku[0] || ku[2])) findings += CertFinding(
                    "KEY_USAGE_TLS_SERVER", "error",
                    "TLS 服务器证书 keyUsage 需含 digitalSignature(bit0) 或 keyEncipherment(bit2)"
                ) else findings += CertFinding("KEY_USAGE_OK", "info", "keyUsage 满足 TLS 服务器要求")
            } else if (p == Eku.CLIENT_AUTH) {
                if (!ku[0]) findings += CertFinding(
                    "KEY_USAGE_TLS_CLIENT", "error",
                    "TLS 客户端证书 keyUsage 需含 digitalSignature(bit0)"
                ) else findings += CertFinding("KEY_USAGE_OK", "info", "keyUsage 满足 TLS 客户端要求")
            }
        }
    }

    private fun checkEku(
        cert: CertInfo,
        isAnchor: Boolean,
        index: Int,
        findings: MutableList<CertFinding>
    ) {
        if (isAnchor) return
        val isLeaf = index == 0
        if (!isLeaf) return
        if (purpose == null) return
        val required = Eku.oid(purpose)
        if (cert.extendedKeyUsage.isEmpty()) {
            findings += CertFinding("EKU_ANY", "info", "叶子证书无 EKU 扩展（任意用途）")
            return
        }
        if (required !in cert.extendedKeyUsage) {
            findings += CertFinding("EKU_MISMATCH", "error",
                "叶子证书 EKU=${cert.extendedKeyUsage.map(Eku::label)} 不含要求用途 ${Eku.label(required)}")
        } else {
            findings += CertFinding("EKU_OK", "info", "叶子证书 EKU 含 ${Eku.label(required)}")
        }
    }

    private fun checkAlgorithmPolicy(cert: CertInfo, findings: MutableList<CertFinding>) {
        val families = listOf(cert.sigHashFamily, cert.sigKeyFamily, cert.publicKeyFamily)
        var retiredFamily: String? = null
        var retiredAt: Instant? = null
        for (f in families) {
            val whenRetired = policy.isRetired(f, at)
            if (whenRetired != null) {
                retiredFamily = f
                retiredAt = whenRetired
                break
            }
        }
        if (retiredFamily != null && retiredAt != null) {
            findings += CertFinding("ALGORITHM_RETIRED", "error",
                "算法 $retiredFamily 在策略版本 ${policy.version} 中已于 $retiredAt 淘汰，" +
                    "验证时刻 $at 不得使用（签名=${cert.sigAlgName}，公钥=${cert.publicKeyFamily}）")
            return
        }
        val minBits = when (cert.publicKeyFamily) {
            "RSA" -> policy.minKeyBitsRsa
            "EC" -> policy.minKeyBitsEc
            else -> null
        }
        if (minBits != null && cert.publicKeyBits < minBits) {
            findings += CertFinding("WEAK_KEY", "error",
                "公钥强度不足：${cert.publicKeyFamily} ${cert.publicKeyBits} 位，" +
                    "策略版本 ${policy.version} 要求至少 $minBits 位")
            return
        }
        findings += CertFinding("ALGORITHM_OK", "info",
            "算法与强度符合策略版本 ${policy.version}：${cert.sigAlgName}，" +
                "${cert.publicKeyFamily} ${cert.publicKeyBits} 位")
    }

    private fun checkHostname(cert: CertInfo, findings: MutableList<CertFinding>) {
        val host = hostname?.trim().orEmpty()
        if (host.isEmpty()) {
            findings += CertFinding("HOSTNAME_SKIPPED", "info", "未提供主机名，跳过名称匹配")
            return
        }
        val matched = if (looksLikeIp(host)) {
            cert.presentedIpNames().any { it == host }
        } else {
            val dnsNames = cert.presentedDnsNames()
            dnsNames.any { dnsMatches(host, it) }
        }
        if (matched) {
            findings += CertFinding("HOSTNAME_OK", "info", "主机名 $host 与证书名称匹配")
        } else {
            val presented = cert.sanDns + cert.sanIp + listOfNotNull(cert.commonName)
            findings += CertFinding("HOSTNAME_MISMATCH", "error",
                "主机名 $host 不匹配证书中的任何名称：${presented.ifEmpty { listOf("(无 SAN/CN)") }}")
        }
    }

    private fun looksLikeIp(host: String): Boolean =
        host.contains(':') || host.split('.').let { parts ->
            parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
        }

    private fun dnsMatches(host: String, pattern: String): Boolean {
        val h = host.trimEnd('.').lowercase()
        val p = pattern.trimEnd('.').lowercase()
        if (h.isEmpty() || p.isEmpty()) return false
        if (!p.contains('*')) return h == p
        val star = p.indexOf('*')
        if (star != p.lastIndexOf('*')) return false
        val before = p.substring(0, star)
        val after = p.substring(star + 1)
        if (!h.endsWith(after)) return false
        val prefix = h.substring(0, h.length - after.length)
        if (!prefix.startsWith(before)) return false
        val wildcardLabel = h.removeSuffix(after).removePrefix(before)
        // 通配符只匹配最左标签，且至少一个字符、不含点
        return wildcardLabel.isNotEmpty() && '.' !in wildcardLabel
    }

    private fun checkNameConstraints(order: List<CertInfo>, byIndex: MutableMap<Int, EvaluatedCert>) {
        if (order.size < 2) return
        val permitted = mutableListOf<Pair<NameConstraint, CertInfo>>()
        val excluded = mutableListOf<Pair<NameConstraint, CertInfo>>()
        // 从 anchor 向下：先放 anchor 的约束，再依次中间 CA
        for (index in order.size - 1 downTo 1) {
            val ca = order[index]
            ca.nameConstraints.permitted.forEach { permitted += it to ca }
            ca.nameConstraints.excluded.forEach { excluded += it to ca }
        }
        if (permitted.isEmpty() && excluded.isEmpty()) return
        for (index in 0 until order.size - 1) {
            val cert = order[index]
            val violations = mutableListOf<String>()
            for (c in cert.sanDns) {
                for ((constraint, ca) in permitted) {
                    if (constraint.type == "dns" && !dnsInSubtree(c, constraint.value)) {
                        violations += "DNS 名称 $c 不在 CA ${ca.labeledName()} 许可子树 ${constraint.value} 内"
                    }
                }
                for ((constraint, ca) in excluded) {
                    if (constraint.type == "dns" && dnsInSubtree(c, constraint.value)) {
                        violations += "DNS 名称 $c 落入 CA ${ca.labeledName()} 排除子树 ${constraint.value}"
                    }
                }
            }
            for (c in cert.sanIp) {
                for ((constraint, ca) in permitted) {
                    if (constraint.type == "ip" && !ipInSubtree(c, constraint.value)) {
                        violations += "IP $c 不在 CA ${ca.labeledName()} 许可子树 ${constraint.value} 内"
                    }
                }
                for ((constraint, ca) in excluded) {
                    if (constraint.type == "ip" && ipInSubtree(c, constraint.value)) {
                        violations += "IP $c 落入 CA ${ca.labeledName()} 排除子树 ${constraint.value}"
                    }
                }
            }
            for ((constraint, ca) in permitted) {
                if (constraint.type == "directory" && !dnWithin(cert.subjectDn, constraint.value)) {
                    violations += "Subject ${cert.subjectDn} 不满足 CA ${ca.labeledName()} 的 directoryName 许可 ${constraint.value}"
                }
            }
            for ((constraint, ca) in excluded) {
                if (constraint.type == "directory" && dnWithin(cert.subjectDn, constraint.value)) {
                    violations += "Subject ${cert.subjectDn} 落入 CA ${ca.labeledName()} 的 directoryName 排除子树 ${constraint.value}"
                }
            }
            if (violations.isNotEmpty()) {
                val findings = byIndex.getValue(index).findings.toMutableList()
                violations.forEach {
                    findings += CertFinding("NAME_CONSTRAINTS_VIOLATION", "error", it)
                }
                byIndex[index] = byIndex.getValue(index).copy(findings = findings)
            }
        }
    }

    private fun dnsInSubtree(name: String, subtree: String): Boolean {
        val n = name.trimEnd('.').lowercase()
        val s = subtree.trimEnd('.').lowercase()
        if (s.isEmpty()) return true
        return n == s || n.endsWith(".$s")
    }

    private fun ipInSubtree(ip: String, subtree: String): Boolean = runCatching {
        if ('/' in subtree) {
            val (net, bitsStr) = subtree.split('/')
            val bits = bitsStr.toInt()
            val addr = java.net.InetAddress.getByName(ip).address
            val netAddr = java.net.InetAddress.getByName(net).address
            if (addr.size != netAddr.size) return false
            var full = bits / 8
            val rem = bits % 8
            for (i in 0 until full) if (addr[i] != netAddr[i]) return false
            if (rem > 0 && full < addr.size) {
                val mask = (0xFF shl (8 - rem)) and 0xFF
                if ((addr[full].toInt() and mask) != (netAddr[full].toInt() and mask)) return false
            }
            true
        } else {
            ip == subtree
        }
    }.getOrDefault(false)

    private fun dnWithin(subject: String, permittedDn: String): Boolean {
        val s = org.bouncycastle.asn1.x500.X500Name(subject)
        val p = org.bouncycastle.asn1.x500.X500Name(permittedDn)
        val rdnCount = p.rdNs.size
        if (s.rdNs.size < rdnCount) return false
        // X500Name 的 RDN 序列：subject 必须以 permitted 的 RDN 序列结尾（从根起）
        val offset = s.rdNs.size - rdnCount
        for (i in 0 until rdnCount) {
            if (s.rdNs[offset + i] != p.rdNs[i]) return false
        }
        return true
    }
}
