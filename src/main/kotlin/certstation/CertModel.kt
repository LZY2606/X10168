package certstation

import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import javax.security.auth.x500.X500Principal

data class GeneralName(
    val type: Int, // 1=email,2=DNS,6=URI,7=IP,4=directoryName
    val value: String
)

data class NameConstraintsData(
    val permitted: List<GeneralName>,
    val excluded: List<GeneralName>
)

data class CertInfo(
    val cert: X509Certificate,
    val fingerprint: String,
    val subjectDn: String,
    val issuerDn: String,
    val subjectCanonical: String,
    val issuerCanonical: String,
    val isSelfSigned: Boolean,
    val subjectKeyId: String?,
    val authorityKeyId: String?,
    val basicConstraints: Int, // -1 = not a CA; >=0 = CA with optional pathLen
    val keyUsage: BooleanArray?,
    val extKeyUsage: List<String>?,
    val san: List<GeneralName>,
    val nameConstraints: NameConstraintsData?
) {
    val isCa: Boolean get() = basicConstraints >= 0
    val pathLen: Int? get() = if (basicConstraints > 0 || basicConstraints == 0) basicConstraints else null

    fun cn(): String? {
        val canon = subjectDn
        // best-effort CN extraction from the RFC2253 string (reversed order)
        val parts = canon.split(",")
        for (p in parts) {
            val kv = p.trim().split("=", limit = 2)
            if (kv.size == 2 && kv[0].equals("CN", ignoreCase = true)) return kv[1].trim()
        }
        return null
    }

    override fun equals(other: Any?): Boolean = other is CertInfo && fingerprint == other.fingerprint
    override fun hashCode(): Int = fingerprint.hashCode()
}

object CertModel {
    private val B64 = Base64.getEncoder()
    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    fun hex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            out[i * 2] = HEX_CHARS[(bytes[i].toInt() ushr 4) and 0xF]
            out[i * 2 + 1] = HEX_CHARS[bytes[i].toInt() and 0xF]
        }
        return String(out)
    }

    fun fingerprint(der: ByteArray): String =
        "sha256:" + hex(MessageDigest.getInstance("SHA-256").digest(der))

    fun describe(cert: X509Certificate): CertInfo {
        val der = cert.encoded
        val fp = fingerprint(der)
        val subjC = cert.subjectX500Principal.getName(X500Principal.CANONICAL)
        val issC = cert.issuerX500Principal.getName(X500Principal.CANONICAL)
        return CertInfo(
            cert = cert,
            fingerprint = fp,
            subjectDn = cert.subjectX500Principal.toString(),
            issuerDn = cert.issuerX500Principal.toString(),
            subjectCanonical = subjC,
            issuerCanonical = issC,
            isSelfSigned = subjC == issC,
            subjectKeyId = extOctetString(cert, "2.5.29.14")?.let { B64.encodeToString(it) },
            authorityKeyId = parseAuthorityKeyId(cert),
            basicConstraints = cert.basicConstraints,
            keyUsage = cert.keyUsage,
            extKeyUsage = try { cert.extendedKeyUsage } catch (_: Exception) { null },
            san = parseSan(cert),
            nameConstraints = parseNameConstraints(cert)
        )
    }

    private fun extRaw(cert: X509Certificate, oid: String): ByteArray? {
        val bytes = cert.getExtensionValue(oid) ?: return null
        // Extension wrapping: OCTET STRING { actual DER }
        val outer = DerReader(bytes).readTag(0x04)
        return outer.content
    }

    private fun extOctetString(cert: X509Certificate, oid: String): ByteArray? {
        val raw = extRaw(cert, oid) ?: return null
        return DerReader(raw).readTag(0x04).content
    }

    private fun parseAuthorityKeyId(cert: X509Certificate): String? {
        val raw = extRaw(cert, "2.5.29.35") ?: return null
        val r = DerReader(raw)
        val seq = r.readTag(0x30)
        val sr = seq.reader()
        while (sr.remaining() > 0) {
            val tlv = sr.readTlv()
            if (tlv.tag == 0x80) return B64.encodeToString(tlv.content) // [0] keyIdentifier
            // [1] authorityCertIssuer / [2] serialNumber are ignored for key id
        }
        return null
    }

    private fun parseSan(cert: X509Certificate): List<GeneralName> {
        // Prefer JDK parsing for the common tag types we care about.
        val names = try { cert.subjectAlternativeNames } catch (_: Exception) { null } ?: return emptyList()
        return names.mapNotNull { entry ->
            val type = (entry[0] as? Int) ?: return@mapNotNull null
            val v = entry[1]
            val text = when (v) {
                is String -> v
                is ByteArray -> ipToString(v)
                else -> v.toString()
            }
            GeneralName(type, text)
        }
    }

    fun parseNameConstraints(cert: X509Certificate): NameConstraintsData? {
        val raw = extRaw(cert, "2.5.29.30") ?: return null
        val r = DerReader(raw)
        val seq = r.readTag(0x30)
        val sr = seq.reader()
        var permitted = emptyList<GeneralName>()
        var excluded = emptyList<GeneralName>()
        while (sr.remaining() > 0) {
            val t = sr.readTlv()
            when (t.tag) {
                0xA0 -> permitted = parseGeneralNamesSubtree(t)
                0xA1 -> excluded = parseGeneralNamesSubtree(t)
            }
        }
        return NameConstraintsData(permitted, excluded)
    }

    private fun parseGeneralNamesSubtree(tlv: DerReader.Tlv): List<GeneralName> {
        val r = tlv.reader()
        val out = ArrayList<GeneralName>()
        while (r.remaining() > 0) {
            val subtree = r.readTag(0x30) // GeneralSubtree
            val sr = subtree.reader()
            val gn = sr.readTlv() // GeneralName (choice)
            val name = generalName(gn)
            if (name != null) out += name
            // minimum/maximum fields ignored
        }
        return out
    }

    private fun generalName(tlv: DerReader.Tlv): GeneralName? {
        val tag = tlv.tag
        val text: String = when (tag and 0xFF) {
            in 0x80..0x8F -> {
                val inner = tlv.content
                when (tag) {
                    0x82 -> String(inner, Charsets.UTF_8) // dNSName [2]
                    0x86 -> String(inner, Charsets.UTF_8) // uniformResourceIdentifier [6]
                    0x81 -> String(inner, Charsets.UTF_8) // rfc822Name [1]
                    0x87 -> ipToString(inner) // iPAddress [7]
                    0xA4 -> // directoryName [4] EXPLICIT; content is the full Name TLV
                        javax.security.auth.x500.X500Principal(tlv.content)
                            .getName(javax.security.auth.x500.X500Principal.CANONICAL)
                    else -> return null
                }
            }
            else -> return null
        }
        val type = tag and 0x1F
        return GeneralName(type, text)
    }

    fun ipToString(bytes: ByteArray): String = when (bytes.size) {
        4 -> bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
        16 -> {
            val parts = (0 until 8).map {
                ((bytes[it * 2].toInt() and 0xFF) shl 8) or (bytes[it * 2 + 1].toInt() and 0xFF)
            }
            java.net.Inet6Address.getByAddress(bytes).hostAddress?.replace("%.*".toRegex(), "")
                ?: parts.joinToString(":") { it.toString(16) }
        }
        else -> bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }
}
