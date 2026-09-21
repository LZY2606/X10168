package certstation

import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64

object Service {
    private const val PROOF_VERSION = "cert-chain-checkpoint/proof/v1"

    fun toPem(cert: X509Certificate): String {
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded)
        return "-----BEGIN CERTIFICATE-----\n$b64\n-----END CERTIFICATE-----\n"
    }

    fun certDto(info: CertInfo, index: Int? = null): Map<String, Any?> = linkedMapOf(
        "index" to index,
        "fingerprint" to info.fingerprint,
        "subject" to info.subjectDn,
        "issuer" to info.issuerDn,
        "serialNumber" to info.cert.serialNumber.toString(16),
        "notBefore" to info.cert.notBefore.toInstant().toString(),
        "notAfter" to info.cert.notAfter.toInstant().toString(),
        "isCa" to info.isCa,
        "pathLenConstraint" to info.pathLen,
        "subjectKeyId" to info.subjectKeyId,
        "authorityKeyId" to info.authorityKeyId,
        "signatureAlgorithm" to AlgorithmInfo.of(info.cert).display,
        "key" to AlgorithmInfo.keyOf(info.cert).display,
        "san" to info.san.map { linkedMapOf("type" to it.type, "value" to it.value) },
        "selfSigned" to info.isSelfSigned
    )

    fun findingDto(f: Finding): Map<String, Any?> = linkedMapOf(
        "code" to f.code,
        "certIndex" to f.certIndex,
        "fingerprint" to f.fingerprint,
        "subject" to f.subject,
        "detail" to f.detail,
        "constraint" to f.constraint,
        "location" to f.location()
    )

    fun reportDto(r: ChainReport, selected: Boolean): Map<String, Any?> = linkedMapOf(
        "complete" to r.candidate.complete,
        "selected" to selected,
        "accepted" to r.accepted,
        "anchorId" to r.candidate.anchor?.id,
        "anchorPriority" to r.candidate.anchor?.priority,
        "length" to r.candidate.certificates.size,
        "chainFingerprint" to r.candidate.chainFingerprint,
        "certificates" to r.candidate.certificates.mapIndexed { i, c -> certDto(c, i) },
        "findings" to r.findings.map { findingDto(it) }
    )

    fun resultDto(result: CheckResult, includePem: Boolean, inputPemByFp: Map<String, String>): Map<String, Any?> = linkedMapOf(
        "verifyAt" to result.verifyAt.toString(),
        "leafFingerprint" to result.leafFingerprint,
        "activePolicies" to result.activePolicies.map {
            linkedMapOf(
                "id" to it.id, "effectiveAt" to it.effectiveAt.toString(),
                "kind" to it.kind, "target" to it.target, "minSize" to it.minSize, "reason" to it.reason
            )
        },
        "pemErrors" to result.pemErrors.map {
            linkedMapOf("blockIndex" to it.blockIndex, "label" to it.label, "code" to it.reason, "message" to it.message)
        },
        "duplicateBlocks" to result.duplicateBlocks,
        "selectedChain" to result.selected?.let { reportDto(it, true) },
        "candidates" to result.reports.map { reportDto(it, result.selected === it) }
    ).let { if (includePem) it + ("pemByFingerprint" to inputPemByFp) else it }

    fun proofDto(result: CheckResult, req: CheckRequest, sessionRev: Long, anchors: List<TrustAnchor>): Map<String, Any?> {
        val selected = result.selected
        return linkedMapOf(
            "format" to PROOF_VERSION,
            "generatedAt" to Instant.now().toString(),
            "verifyAt" to result.verifyAt.toString(),
            "host" to req.host,
            "eku" to req.eku,
            "sessionRevision" to sessionRev,
            "containsPrivateKey" to false,
            "activePolicies" to result.activePolicies.map {
                linkedMapOf("id" to it.id, "effectiveAt" to it.effectiveAt.toString(), "kind" to it.kind,
                    "target" to it.target, "minSize" to it.minSize, "reason" to it.reason)
            },
            "trustAnchors" to anchors.map {
                linkedMapOf(
                    "id" to it.id, "priority" to it.priority,
                    "fingerprint" to it.info.fingerprint, "subject" to it.info.subjectDn
                )
            },
            "selectedChain" to selected?.let { r ->
                linkedMapOf(
                    "chainFingerprint" to r.candidate.chainFingerprint,
                    "anchorId" to r.candidate.anchor?.id,
                    "certificates" to r.candidate.certificates.map { c ->
                        certDto(c) + mapOf("pem" to toPem(c.cert))
                    }
                )
            },
            "rejectedChains" to result.reports.filterNot { it === selected }.map { r ->
                linkedMapOf(
                    "chainFingerprint" to r.candidate.chainFingerprint,
                    "accepted" to r.accepted,
                    "anchorId" to r.candidate.anchor?.id,
                    "length" to r.candidate.certificates.size,
                    "leafFingerprint" to r.candidate.certificates.first().fingerprint,
                    "reasons" to r.findings.map { findingDto(it) }
                )
            },
            "parseErrors" to result.pemErrors.map {
                linkedMapOf("blockIndex" to it.blockIndex, "label" to it.label, "code" to it.reason, "message" to it.message)
            },
            "duplicateBlocksDropped" to result.duplicateBlocks
        )
    }

    fun runCheck(
        pemText: String,
        anchors: List<TrustAnchor>,
        policy: AlgorithmPolicy,
        verifyAt: Instant,
        host: String,
        eku: String,
        leafFingerprint: String?
    ): Triple<ParsedPem, CheckRequest, CheckResult> {
        val parsed = PemParser.parse(pemText)
        val req = CheckRequest(verifyAt = verifyAt, host = host.trim(), eku = eku.trim(), policy = policy)
        val result = Validator.check(parsed, anchors, req, leafFingerprint?.ifBlank { null })
        return Triple(parsed, req, result)
    }
}
