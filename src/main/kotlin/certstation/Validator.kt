package certstation

import java.time.Instant
import java.util.Date

data class Finding(
    val code: String,
    val certIndex: Int, // 0 = leaf; the anchor is the last index
    val fingerprint: String,
    val subject: String,
    val detail: String,
    val constraint: String? = null
) {
    fun location(): String = "证书[#$certIndex] ${shortSubject()} ($fingerprint)"
    fun shortSubject(): String = subject.substringAfter("CN=", subject).substringBefore(",").trim()
}

data class CheckRequest(
    val verifyAt: Instant,
    val host: String = "",
    val eku: String = SERVER_AUTH, // "" disables EKU/key-purpose checks
    val policy: AlgorithmPolicy = AlgorithmPolicy()
) {
    companion object {
        const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
        const val CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    }
}

data class ChainReport(
    val candidate: ChainCandidate,
    val findings: List<Finding>,
    val accepted: Boolean
)

data class CheckResult(
    val reports: List<ChainReport>,
    val selected: ChainReport?,
    val verifyAt: Instant,
    val activePolicies: List<PolicyEntry>,
    val pemErrors: List<PemError>,
    val duplicateBlocks: Int,
    val leafFingerprint: String?
)

object Validator {

    fun check(
        parsed: ParsedPem,
        anchors: List<TrustAnchor>,
        request: CheckRequest,
        leafFingerprint: String? = null
    ): CheckResult {
        val infos = parsed.certificates.map { CertModel.describe(it) }
        val candidates = ChainBuilder.enumerate(infos, anchors, leafFingerprint)
        val reports = candidates.map { validateChain(it, request) }

        val accepted = reports.filter { it.accepted }
        val selected = accepted.minWithOrNull(chainComparator(request))
        return CheckResult(
            reports = reports,
            selected = selected,
            verifyAt = request.verifyAt,
            activePolicies = request.policy.activeAt(request.verifyAt),
            pemErrors = parsed.errors,
            duplicateBlocks = parsed.duplicateBlocks,
            leafFingerprint = selected?.candidate?.certificates?.firstOrNull()?.fingerprint
                ?: leafFingerprint
        )
    }

    private fun chainComparator(@Suppress("UNUSED_PARAMETER") request: CheckRequest): Comparator<ChainReport> =
        compareBy(
            { it.candidate.certificates.size },
            { it.candidate.anchor?.priority ?: Int.MAX_VALUE },
            { it.candidate.chainFingerprint }
        )

    private fun validateChain(candidate: ChainCandidate, req: CheckRequest): ChainReport {
        val findings = ArrayList<Finding>()
        val chain = candidate.certificates
        val anchorFp = candidate.anchor?.info?.fingerprint
        val lastIndex = chain.size - 1

        if (!candidate.complete) {
            val tail = chain.last()
            findings += Finding(
                "NO_TRUST_ANCHOR",
                chain.size - 1,
                tail.fingerprint,
                tail.subjectDn,
                "链在该证书处终止，未到达会话显式提供的 trust anchor（不使用系统信任库）"
            )
        }

        // 1) Signature verification for every certificate except the terminal anchor.
        for (i in 0 until chain.size - 1) {
            val child = chain[i]
            val parent = chain[i + 1]
            try {
                child.cert.verify(parent.cert.publicKey)
            } catch (e: Exception) {
                findings += Finding(
                    "SIGNATURE_INVALID", i, child.fingerprint, child.subjectDn,
                    "无法用签发者公钥验证签名：${e.javaClass.simpleName} ${e.message}",
                    constraint = "签发者: ${parent.subjectDn}"
                )
            }
        }
        // If the chain is complete but the terminal node does not match the anchor record,
        // signature against anchor must also hold; covered above unless terminal == anchor.

        // 2) Time validity. Equal notBefore is valid; equal notAfter is expired. UTC.
        val at = Date.from(req.verifyAt)
        for (i in chain.indices) {
            val c = chain[i]
            val isAnchor = c.fingerprint == anchorFp && i == lastIndex
            if (at.before(c.cert.notBefore)) {
                val code = if (isAnchor) "ANCHOR_NOT_YET_VALID_INFO" else "NOT_YET_VALID"
                findings += Finding(
                    code, i, c.fingerprint, c.subjectDn,
                    "验证时刻 ${req.verifyAt} 早于 notBefore ${toInstant(c.cert.notBefore)}"
                )
            }
            // notAfter inclusive: valid iff at < notAfter, so >= means expired.
            if (!at.before(c.cert.notAfter)) {
                val code = if (isAnchor) "ANCHOR_EXPIRED_INFO" else "EXPIRED"
                findings += Finding(
                    code, i, c.fingerprint, c.subjectDn,
                    "验证时刻 ${req.verifyAt} 已等于/晚于 notAfter ${toInstant(c.cert.notAfter)}（notAfter 当天即过期）"
                )
            }
        }

        // 3) Basic constraints.
        for (i in chain.indices) {
            val c = chain[i]
            val isAnchor = c.fingerprint == anchorFp && i == lastIndex
            if (isAnchor) continue
            if (i == 0) {
                if (c.isCa) findings += Finding(
                    "LEAF_IS_CA", i, c.fingerprint, c.subjectDn,
                    "末端实体证书带有 cA=true，不能作为 TLS 证书"
                )
            } else {
                if (!c.isCa) findings += Finding(
                    "MISSING_BASIC_CONSTRAINTS_CA", i, c.fingerprint, c.subjectDn,
                    "中间证书不是 CA（basicConstraints.cA 缺失或为 false）",
                    constraint = "2.5.29.19"
                )
            }
        }

        // 4) Path length. For CA at index i, non-self-issued CA certificates below it
        //    (indices 1..i-1) must be <= pathLenConstraint.
        for (i in 1 until chain.size) {
            val ca = chain[i]
            val isAnchor = ca.fingerprint == anchorFp && i == lastIndex
            if (!ca.isCa) continue
            val maxLen = ca.pathLen ?: continue
            // number of CA certs between leaf and this CA
            val intermediatesBelow = (1 until i).count { j ->
                chain[j].isCa && !isSelfIssued(chain[j], ca)
            }
            if (intermediatesBelow > maxLen) {
                val code = if (isAnchor) "PATH_LEN_ANCHOR" else "PATH_LEN_EXCEEDED"
                findings += Finding(
                    code, i, ca.fingerprint, ca.subjectDn,
                    "pathLenConstraint=$maxLen，但其下方有 $intermediatesBelow 个中间 CA",
                    constraint = "2.5.29.19"
                )
            }
        }

        // 5) Key usage.
        for (i in chain.indices) {
            val c = chain[i]
            val ku = c.keyUsage ?: continue
            val isAnchor = c.fingerprint == anchorFp && i == lastIndex
            if (i == 0 && !isAnchor) {
                if (!ku[0]) findings += Finding(
                    "KEY_USAGE_DIGITAL_SIGNATURE", i, c.fingerprint, c.subjectDn,
                    "末端证书缺少 keyUsage.digitalSignature",
                    constraint = "2.5.29.15 bit0"
                )
            } else if (c.isCa) {
                if (!ku[5]) findings += Finding(
                    "KEY_USAGE_KEY_CERT_SIGN", i, c.fingerprint, c.subjectDn,
                    "CA 证书缺少 keyUsage.keyCertSign",
                    constraint = "2.5.29.15 bit5"
                )
            }
        }

        // 6) Extended key usage (purpose).
        if (req.eku.isNotBlank()) {
            val leaf = chain.first()
            if (!leaf.isCa) {
                val ekus = leaf.extKeyUsage
                if (ekus != null && ekus.none { it == req.eku || it == ANY_EKU }) {
                    findings += Finding(
                        "EKU_MISMATCH", 0, leaf.fingerprint, leaf.subjectDn,
                        "末端证书 EKU $ekus 不包含用途 ${ekuName(req.eku)} ($req.eku)",
                        constraint = "2.5.29.37"
                    )
                }
            }
            for (i in 1 until chain.size) {
                val c = chain[i]
                val isAnchor = c.fingerprint == anchorFp && i == lastIndex
                val ekus = c.extKeyUsage ?: continue
                // An intermediate that constrains purposes must include the requested one.
                if (!isAnchor && ekus.none { it == req.eku || it == ANY_EKU }) {
                    findings += Finding(
                        "EKU_INTERMEDIATE_MISMATCH", i, c.fingerprint, c.subjectDn,
                        "中间证书 EKU $ekus 不包含用途 ${ekuName(req.eku)}，且非 anyExtendedKeyUsage",
                        constraint = "2.5.29.37"
                    )
                }
            }
        }

        // 7) Name constraints of every CA in the chain apply to the leaf.
        val leaf = chain.first()
        for (i in 1 until chain.size) {
            val c = chain[i]
            val nc = c.nameConstraints ?: continue
            val problems = HostnameMatcher.checkConstraints(nc, leaf, req.host)
            for (p in problems) {
                findings += Finding(
                    "NAME_CONSTRAINTS", i, c.fingerprint, c.subjectDn, p,
                    constraint = "2.5.29.30"
                )
            }
        }

        // 8) Hostname matching on the leaf.
        if (req.host.isNotBlank() && !leaf.isCa) {
            if (!HostnameMatcher.certMatches(leaf, req.host)) {
                val names = HostnameMatcher.certDnsNames(leaf)
                findings += Finding(
                    "HOSTNAME_MISMATCH", 0, leaf.fingerprint, leaf.subjectDn,
                    "主机名 '${req.host}' 与证书不匹配（SAN/CN=$names）",
                    constraint = "2.5.29.17"
                )
            }
        }

        // 9) Algorithm / key-size policy replay.
        for (i in chain.indices) {
            val c = chain[i]
            for (v in PolicyEvaluator.evaluate(c.cert, req.policy, req.verifyAt)) {
                findings += Finding(
                    v.code, i, c.fingerprint, c.subjectDn,
                    "${v.message}（策略 ${v.entryId} 生效于 ${v.effectiveAt}，按 ${req.verifyAt} 时刻重放）",
                    constraint = v.entryId
                )
            }
        }

        val blocking = findings.none { it.code !in INFO_CODES }
        return ChainReport(candidate, findings, blocking)
    }

    private val INFO_CODES = setOf(
        "ANCHOR_NOT_YET_VALID_INFO", "ANCHOR_EXPIRED_INFO", "PATH_LEN_ANCHOR"
    )

    private const val ANY_EKU = "2.5.29.37.0"

    private fun isSelfIssued(child: CertInfo, parent: CertInfo): Boolean =
        child.subjectCanonical == parent.subjectCanonical

    private fun toInstant(d: Date): Instant = d.toInstant()

    fun ekuName(oid: String): String = when (oid) {
        CheckRequest.SERVER_AUTH -> "serverAuth"
        CheckRequest.CLIENT_AUTH -> "clientAuth"
        "1.3.6.1.5.5.7.3.3" -> "codeSigning"
        "1.3.6.1.5.5.7.3.4" -> "emailProtection"
        ANY_EKU -> "anyExtendedKeyUsage"
        else -> oid
    }
}
