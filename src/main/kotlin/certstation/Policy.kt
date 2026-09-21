package certstation

import java.security.cert.X509Certificate
import java.time.Instant
import java.util.TreeMap

/**
 * Algorithm policy. Entries are activated by [effectiveAt]: when replaying a check at
 * a past instant, only entries with effectiveAt <= the verification instant apply.
 */
data class PolicyEntry(
    val id: String,
    val effectiveAt: Instant,
    /** "retire-signature-algo" or "min-key-size". */
    val kind: String,
    /** For retire: signature family/name token, e.g. "MD5", "SHA1", "RSA-1024". For min-key: key family, e.g. "RSA", "EC". */
    val target: String,
    val minSize: Int = 0,
    val reason: String = ""
)

data class AlgorithmPolicy(val entries: List<PolicyEntry> = DEFAULT_ENTRIES) {

    fun activeAt(instant: Instant): List<PolicyEntry> =
        entries.filter { !it.effectiveAt.isAfter(instant) }.sortedBy { it.effectiveAt }

    companion object {
        val DEFAULT_ENTRIES = listOf(
            PolicyEntry(
                "default-sha1-retire",
                Instant.parse("2017-01-01T00:00:00Z"),
                "retire-signature-algo", "SHA1",
                reason = "默认策略：SHA-1 签名自 2017-01-01 起退役"
            ),
            PolicyEntry(
                "default-md5-retire",
                Instant.parse("2005-01-01T00:00:00Z"),
                "retire-signature-algo", "MD5",
                reason = "默认策略：MD5 签名自 2005-01-01 起退役"
            ),
            PolicyEntry(
                "default-rsa-min2048",
                Instant.parse("2014-01-01T00:00:00Z"),
                "min-key-size", "RSA", minSize = 2048,
                reason = "默认策略：RSA 最小密钥长度自 2014-01-01 起为 2048 位"
            )
        )
    }
}

object AlgorithmInfo {
    data class Sig(val family: String, val digest: String?, val display: String)

    fun of(cert: X509Certificate): Sig {
        val oid = cert.sigAlgOID
        val params = cert.sigAlgName.uppercase()
        return when (oid) {
            "1.2.840.113549.1.1.2" -> Sig("RSA", "MD2", "MD2withRSA")
            "1.2.840.113549.1.1.4" -> Sig("RSA", "MD5", "MD5withRSA")
            "1.2.840.113549.1.1.5" -> Sig("RSA", "SHA1", "SHA1withRSA")
            "1.2.840.113549.1.1.11" -> Sig("RSA", "SHA256", "SHA256withRSA")
            "1.2.840.113549.1.1.12" -> Sig("RSA", "SHA384", "SHA384withRSA")
            "1.2.840.113549.1.1.13" -> Sig("RSA", "SHA512", "SHA512withRSA")
            "1.2.840.113549.1.1.10" -> {
                val digest = when {
                    params.contains("SHA256") -> "SHA256"
                    params.contains("SHA384") -> "SHA384"
                    params.contains("SHA512") -> "SHA512"
                    else -> "SHA256"
                }
                Sig("RSA-PSS", digest, "RSASSA-PSS/$digest")
            }
            "1.2.840.10040.4.3" -> Sig("DSA", "SHA1", "SHA1withDSA")
            "2.16.840.1.101.3.4.3.2" -> Sig("DSA", "SHA256", "SHA256withDSA")
            "1.2.840.10045.4.1" -> Sig("ECDSA", "SHA1", "SHA1withECDSA")
            "1.2.840.10045.4.3.2" -> Sig("ECDSA", "SHA256", "SHA256withECDSA")
            "1.2.840.10045.4.3.3" -> Sig("ECDSA", "SHA384", "SHA384withECDSA")
            "1.2.840.10045.4.3.4" -> Sig("ECDSA", "SHA512", "SHA512withECDSA")
            "1.3.101.112" -> Sig("Ed25519", null, "Ed25519")
            "1.3.101.113" -> Sig("Ed448", null, "Ed448")
            else -> Sig(oid, null, cert.sigAlgName)
        }
    }

    data class KeyInfo(val family: String, val size: Int, val display: String)

    fun keyOf(cert: X509Certificate): KeyInfo {
        val pk = cert.publicKey
        val alg = pk.algorithm.uppercase()
        return when {
            alg == "RSA" -> {
                val size = try {
                    pk as java.security.interfaces.RSAPublicKey
                    pk.modulus.bitLength()
                } catch (_: Exception) { -1 }
                KeyInfo("RSA", size, "RSA-$size")
            }
            alg.startsWith("EC") -> {
                val size = try {
                    val ec = pk as java.security.interfaces.ECPublicKey
                    ec.params.order.bitLength()
                } catch (_: Exception) { -1 }
                KeyInfo("EC", size, "EC-P$size")
            }
            alg == "DSA" -> {
                val size = try {
                    (pk as java.security.interfaces.DSAPublicKey).params.p.bitLength()
                } catch (_: Exception) { -1 }
                KeyInfo("DSA", size, "DSA-$size")
            }
            alg.contains("ED25519") -> KeyInfo("Ed25519", 256, "Ed25519")
            alg.contains("ED448") -> KeyInfo("Ed448", 456, "Ed448")
            else -> KeyInfo(alg, -1, pk.algorithm)
        }
    }
}

data class PolicyViolation(
    val entryId: String,
    val code: String,
    val message: String,
    val effectiveAt: Instant,
    val observed: String
)

object PolicyEvaluator {
    fun evaluate(cert: X509Certificate, policy: AlgorithmPolicy, at: Instant): List<PolicyViolation> {
        val sig = AlgorithmInfo.of(cert)
        val key = AlgorithmInfo.keyOf(cert)
        val out = ArrayList<PolicyViolation>()
        for (e in policy.activeAt(at)) {
            when (e.kind) {
                "retire-signature-algo" -> {
                    val token = e.target.uppercase()
                    val hits = token == sig.family.uppercase() ||
                        (sig.digest != null && token == sig.digest.uppercase()) ||
                        sig.display.uppercase().contains(token)
                    if (hits) out += PolicyViolation(
                        e.id, "ALGORITHM_RETIRED",
                        "${e.reason.ifEmpty { "签名算法已退役" }}（命中 ${e.target}，实际 ${sig.display}）",
                        e.effectiveAt, sig.display
                    )
                }
                "min-key-size" -> {
                    if (key.family.equals(e.target, ignoreCase = true) && key.size >= 0 && key.size < e.minSize) {
                        out += PolicyViolation(
                            e.id, "KEY_TOO_SHORT",
                            "${e.reason.ifEmpty { "密钥长度不足" }}（要求 >= ${e.minSize}，实际 ${key.size}）",
                            e.effectiveAt, key.display
                        )
                    }
                }
            }
        }
        return out
    }
}
