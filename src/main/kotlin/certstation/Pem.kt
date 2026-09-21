package certstation

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

data class ParsedPem(
    val certificates: List<X509Certificate>,
    val fingerprints: LinkedHashSet<String>,
    val errors: List<PemError>,
    val duplicateBlocks: Int
)

data class PemError(val blockIndex: Int, val label: String?, val reason: String, val message: String)

object PemParser {
    private val BLOCK =
        """-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----""".toRegex(RegexOption.DOT_MATCHES_ALL)

    private val PRIVATE_KEY_LABELS = setOf(
        "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY", "PKCS7", "PKCS8"
    )

    fun parse(input: String): ParsedPem {
        val cf = CertificateFactory.getInstance("X.509")
        val certs = ArrayList<X509Certificate>()
        val fps = LinkedHashSet<String>()
        val errors = ArrayList<PemError>()
        var duplicates = 0
        var idx = 0

        val matches = BLOCK.findAll(input).toList()
        if (matches.isEmpty() && input.isNotBlank()) {
            errors += PemError(0, null, "NO_PEM_BLOCK", "未找到任何 PEM 块")
            return ParsedPem(certs, fps, errors, duplicates)
        }

        // Detect malformed BEGIN markers that never form a full block.
        val dangling = """-----BEGIN ([A-Z0-9 ]+)-----""".toRegex().findAll(input)
            .count { m -> matches.none { it.range.first == m.range.first } }
        repeat(dangling) { errors += PemError(idx++, null, "UNTERMINATED_PEM", "存在缺少 END 标记的 PEM 块") }

        for (m in matches) {
            val blockIndex = idx++
            val label = m.groupValues[1].trim()
            if (label in PRIVATE_KEY_LABELS || label.contains("PRIVATE KEY")) {
                errors += PemError(blockIndex, label, "PRIVATE_KEY_REJECTED", "私钥块被拒绝：检查站只接受证书")
                continue
            }
            if (label != "CERTIFICATE" && label != "TRUSTED CERTIFICATE" && label != "X509 CERTIFICATE") {
                errors += PemError(blockIndex, label, "UNSUPPORTED_LABEL", "不支持的 PEM 标签: $label")
                continue
            }
            val b64 = m.groupValues[2].replace("""\s+""".toRegex(), "")
            val der = try {
                java.util.Base64.getDecoder().decode(b64)
            } catch (e: IllegalArgumentException) {
                errors += PemError(blockIndex, label, "BASE64_INVALID", "Base64 解码失败: ${e.message}")
                continue
            }
            val cert = try {
                cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            } catch (e: Exception) {
                errors += PemError(blockIndex, label, "CERT_PARSE_FAILED", "X.509 解析失败: ${e.javaClass.simpleName} ${e.message}")
                continue
            }
            val fp = CertModel.fingerprint(der)
            if (fp in fps) {
                duplicates++
                continue
            }
            fps += fp
            certs += cert
        }
        return ParsedPem(certs, fps, errors, duplicates)
    }
}
