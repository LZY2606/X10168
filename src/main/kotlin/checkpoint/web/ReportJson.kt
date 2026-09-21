package checkpoint.web

import checkpoint.chain.CheckReport

object ReportJson {
    fun toMap(report: CheckReport): Map<String, Any?> = linkedMapOf(
        "sessionId" to report.sessionId,
        "version" to report.version,
        "verifyAt" to report.verifyAt,
        "policyVersionApplied" to report.policyVersionApplied,
        "hostname" to report.hostname,
        "purpose" to report.purpose,
        "anchors" to report.anchors,
        "parsedCertificateCount" to report.parsedCertificateCount,
        "duplicateFingerprints" to report.duplicateFingerprints,
        "parseErrors" to report.parseErrors,
        "selectedChainIndex" to report.selectedChainIndex,
        "chains" to report.chains.map { chain ->
            linkedMapOf(
                "rank" to chain.rank,
                "accepted" to chain.accepted,
                "selected" to chain.selected,
                "length" to chain.length,
                "anchorLabel" to chain.anchorLabel,
                "anchorPriority" to chain.anchorPriority,
                "fingerprint" to chain.fingerprint,
                "terminal" to chain.terminal,
                "rejectReasons" to chain.rejectReasons,
                "certificates" to chain.certificates.map { cert ->
                    linkedMapOf(
                        "index" to cert.index,
                        "role" to cert.role,
                        "subjectDn" to cert.subjectDn,
                        "issuerDn" to cert.issuerDn,
                        "sha256" to cert.sha256,
                        "notBefore" to cert.notBefore,
                        "notAfter" to cert.notAfter,
                        "isCa" to cert.isCa,
                        "pathLenConstraint" to cert.pathLenConstraint,
                        "keyUsage" to cert.keyUsage,
                        "extendedKeyUsage" to cert.eku,
                        "sanDns" to cert.sanDns,
                        "sanIp" to cert.sanIp,
                        "signatureAlgorithm" to cert.signatureAlgorithm,
                        "publicKey" to cert.publicKey,
                        "findings" to cert.findings,
                        "pem" to cert.pem
                    )
                }
            )
        }
    )

    /** 导出的证明：只含公钥证书与策略/参数，结构中没有任何私钥字段。 */
    fun toProofMap(report: CheckReport, bundlePem: String, sourcePolicyJson: Any?): Map<String, Any?> {
        val certPems = report.chains.flatMap { it.certificates.map { c -> c.pem } }.distinct()
        return linkedMapOf(
            "proofType" to "offline-cert-chain-check/v1",
            "generatedAt" to java.time.Instant.now().toString(),
            "offline" to true,
            "containsPrivateKeys" to false,
            "sessionId" to report.sessionId,
            "sessionVersion" to report.version,
            "parameters" to linkedMapOf(
                "verifyAtUtc" to report.verifyAt,
                "hostname" to report.hostname,
                "purpose" to report.purpose,
                "policyVersionApplied" to report.policyVersionApplied
            ),
            "anchors" to report.anchors,
            "policy" to sourcePolicyJson,
            "selectedChainIndex" to report.selectedChainIndex,
            "chains" to report.chains.map { chain ->
                linkedMapOf(
                    "accepted" to chain.accepted,
                    "selected" to chain.selected,
                    "rank" to chain.rank,
                    "length" to chain.length,
                    "anchorLabel" to chain.anchorLabel,
                    "anchorPriority" to chain.anchorPriority,
                    "rejectReasons" to chain.rejectReasons,
                    "certificateSha256" to chain.certificates.map { it.sha256 },
                    "certificates" to chain.certificates.map { cert ->
                        linkedMapOf(
                            "index" to cert.index,
                            "role" to cert.role,
                            "subjectDn" to cert.subjectDn,
                            "issuerDn" to cert.issuerDn,
                            "sha256" to cert.sha256,
                            "notBefore" to cert.notBefore,
                            "notAfter" to cert.notAfter,
                            "signatureAlgorithm" to cert.signatureAlgorithm,
                            "publicKey" to cert.publicKey,
                            "findings" to cert.findings,
                            "pem" to cert.pem
                        )
                    }
                )
            },
            "inputCertificatesPem" to certPems,
            "originalBundlePem" to bundlePem,
            "parseErrors" to report.parseErrors,
            "duplicateFingerprints" to report.duplicateFingerprints
        )
    }
}
