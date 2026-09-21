package checkpoint.chain

import checkpoint.model.CertInfo
import checkpoint.model.CertLoader
import checkpoint.model.PemBlocks
import checkpoint.model.PolicySet
import checkpoint.model.PolicyVersion
import checkpoint.model.TimeUtil
import java.time.Instant

data class AnchorInput(val label: String?, val pem: String)

data class CheckInput(
    val bundlePem: String,
    val anchors: List<AnchorInput>,
    val hostname: String?,
    val purpose: String?,
    val verifyAtText: String,
    val policy: PolicySet
)

data class CertificateReport(
    val index: Int,
    val role: String,
    val subjectDn: String,
    val issuerDn: String,
    val sha256: String,
    val notBefore: String,
    val notAfter: String,
    val isCa: Boolean,
    val pathLenConstraint: Int?,
    val keyUsage: List<String>?,
    val eku: List<String>,
    val sanDns: List<String>,
    val sanIp: List<String>,
    val signatureAlgorithm: String,
    val publicKey: String,
    val pem: String,
    val findings: List<Map<String, String>>
)

data class ChainReport(
    val rank: Int?,
    val accepted: Boolean,
    val selected: Boolean,
    val length: Int,
    val anchorLabel: String?,
    val anchorPriority: Int?,
    val fingerprint: String,
    val terminal: String,
    val rejectReasons: List<String>,
    val certificates: List<CertificateReport>
)

data class CheckReport(
    val sessionId: String?,
    val version: Int?,
    val verifyAt: String,
    val policyVersionApplied: String,
    val hostname: String?,
    val purpose: String?,
    val anchors: List<Map<String, Any?>>,
    val parsedCertificateCount: Int,
    val duplicateFingerprints: List<String>,
    val parseErrors: List<String>,
    val selectedChainIndex: Int?,
    val chains: List<ChainReport>
)

object KeyUsageBits {
    val NAMES = listOf(
        "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
        "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
    )
}

class CheckService {
    fun parseCertificates(pem: String): Pair<List<CertInfo>, List<String>> {
        val pr = PemBlocks.parse(pem)
        val errors = pr.errors.toMutableList()
        val certs = mutableListOf<CertInfo>()
        val seen = mutableSetOf<String>()
        val duplicates = mutableListOf<String>()
        for (block in pr.blocks) {
            val cert = runCatching { CertLoader.fromDer(block.content, blockPem(block.content)) }
                .getOrElse {
                    errors += "第 ${block.index} 个证书块解析失败：${it.message ?: it.javaClass.simpleName}（不影响其他块）"
                    null
                } ?: continue
            if (!seen.add(cert.fingerprintSha256)) {
                duplicates += cert.fingerprintSha256
                errors += "重复证书已按 DER SHA-256 指纹去重：${cert.labeledName()} (${cert.fingerprintSha256.take(16)}…)"
                continue
            }
            certs += cert
        }
        return certs to (errors + duplicates.map { "__DUP__$it" })
    }

    private fun blockPem(der: ByteArray): String {
        val b64 = java.util.Base64.getEncoder().encodeToString(der)
        val wrapped = b64.chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$wrapped\n-----END CERTIFICATE-----"
    }

    private fun parseAnchor(input: AnchorInput): Pair<CertInfo, String>? {
        val pr = PemBlocks.parse(input.pem)
        val block = pr.blocks.firstOrNull()
        if (block == null) return null
        return runCatching { CertLoader.fromDer(block.content, blockPem(block.content)) }
            .getOrNull()?.let { it to (input.label ?: it.labeledName()) }
    }

    fun check(input: CheckInput, sessionId: String? = null, version: Int? = null): CheckReport {
        val verifyAt: Instant = TimeUtil.parseInstant(input.verifyAtText)
        val policyVersion = input.policy.at(verifyAt)

        val (bundleCerts, parseErrorsRaw) = parseCertificates(input.bundlePem)
        val parseErrors = parseErrorsRaw.filterNot { it.startsWith("__DUP__") }
        val duplicates = parseErrorsRaw.filter { it.startsWith("__DUP__") }.map { it.removePrefix("__DUP__") }

        // anchor 内部按指纹去重，保留第一次出现及其标签
        val seenAnchor = mutableSetOf<String>()
        val anchorEntries = input.anchors.mapNotNull { a -> parseAnchor(a) }
            .filter { seenAnchor.add(it.first.fingerprintSha256) }
        val anchors = anchorEntries.map { it.first }
        val anchorLabels = anchorEntries.associate { it.first.fingerprintSha256 to it.second }

        val anchorFps = anchors.map { it.fingerprintSha256 }.toSet()
        val intermediates = bundleCerts.filter { it.fingerprintSha256 !in anchorFps }

        val builder = ChainBuilder(anchors, intermediates)
        val rawChains = builder.enumerate()
        val validator = ChainValidator(verifyAt, policyVersion, input.hostname, input.purpose)
        val evaluated = rawChains.map(validator::evaluate)

        val accepted = evaluated.withIndex()
            .filter { it.value.accepted }
            .sortedWith(compareBy(
                { it.value.order.size },
                { it.value.anchorPriority ?: Int.MAX_VALUE },
                { it.value.fingerprint() }
            ))
        val selectedFp = accepted.firstOrNull()?.value?.fingerprint()

        val reports = evaluated.map { ec ->
            toChainReport(ec, ec.fingerprint() == selectedFp, anchorLabels, null)
        }
        // 展示排序：合格链在前（按选链顺序），失败链在后（长度、指纹稳定）
        val orderedReports = reports.sortedWith(compareBy(
            { if (it.accepted) 0 else 1 },
            { it.length },
            { it.anchorPriority ?: Int.MAX_VALUE },
            { it.fingerprint }
        ))
        val selectedIndex = orderedReports.indexOfFirst { it.selected }.let { if (it < 0) null else it }
        val ranked = orderedReports.mapIndexed { idx, r ->
            if (r.selected) r.copy(rank = idx + 1) else r.copy(rank = null)
        }

        return CheckReport(
            sessionId = sessionId,
            version = version,
            verifyAt = TimeUtil.format(verifyAt),
            policyVersionApplied = policyVersion.version,
            hostname = input.hostname?.takeIf { it.isNotBlank() },
            purpose = input.purpose?.takeIf { it.isNotBlank() },
            anchors = anchors.map {
                mapOf(
                    "label" to (anchorLabels[it.fingerprintSha256] ?: it.labeledName()),
                    "subjectDn" to it.subjectDn,
                    "sha256" to it.fingerprintSha256,
                    "pem" to it.pem
                )
            },
            parsedCertificateCount = bundleCerts.size,
            duplicateFingerprints = duplicates,
            parseErrors = parseErrors,
            selectedChainIndex = selectedIndex,
            chains = ranked
        )
    }

    private fun toChainReport(
        ec: EvaluatedChain,
        selected: Boolean,
        anchorLabels: Map<String, String>,
        rank: Int?
    ): ChainReport {
        val certReports = ec.certs.map { ev ->
            val role = when {
                ev.isAnchor -> "trust-anchor"
                ev.index == 0 -> "leaf"
                else -> "intermediate"
            }
            CertificateReport(
                index = ev.index,
                role = role,
                subjectDn = ev.cert.subjectDn,
                issuerDn = ev.cert.issuerDn,
                sha256 = ev.cert.fingerprintSha256,
                notBefore = TimeUtil.format(ev.cert.notBefore),
                notAfter = TimeUtil.format(ev.cert.notAfter),
                isCa = ev.cert.isCa,
                pathLenConstraint = ev.cert.pathLenConstraint,
                keyUsage = ev.cert.keyUsage?.let { ku ->
                    KeyUsageBits.NAMES.mapIndexedNotNull { i, n -> if (ku[i]) n else null }
                },
                eku = ev.cert.extendedKeyUsage.map(Eku::label),
                sanDns = ev.cert.sanDns,
                sanIp = ev.cert.sanIp,
                signatureAlgorithm = ev.cert.sigAlgName,
                publicKey = "${ev.cert.publicKeyFamily}-${ev.cert.publicKeyBits}",
                pem = ev.cert.pem,
                findings = ev.findings.map { mapOf("code" to it.code, "severity" to it.severity, "message" to it.message) }
            )
        }
        return ChainReport(
            rank = rank,
            accepted = ec.accepted,
            selected = selected,
            length = ec.order.size,
            anchorLabel = ec.anchor?.let { anchorLabels[it.fingerprintSha256] ?: it.labeledName() },
            anchorPriority = ec.anchorPriority,
            fingerprint = ec.fingerprint(),
            terminal = ec.terminal,
            rejectReasons = ec.rejectReasons,
            certificates = certReports
        )
    }
}
