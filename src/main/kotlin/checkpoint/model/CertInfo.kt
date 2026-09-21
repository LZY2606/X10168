package checkpoint.model

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.AttributeTypeAndValue
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.GeneralSubtree
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.NameConstraints
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest
import org.bouncycastle.asn1.x509.BasicConstraints
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64

data class NameConstraint(
    val type: String,   // dns / directory / ip / email
    val value: String
)

data class NameConstraintsData(
    val permitted: List<NameConstraint> = emptyList(),
    val excluded: List<NameConstraint> = emptyList()
) {
    companion object {
        val NONE = NameConstraintsData()
    }
}

data class CertInfo(
    val holder: X509CertificateHolder,
    val x509: X509Certificate,
    val der: ByteArray,
    val pem: String,
    val fingerprintSha256: String,
    val subjectDn: String,
    val issuerDn: String,
    val subjectKeyId: String?,
    val authorityKeyId: String?,
    val basicConstraintsPresent: Boolean,
    val isCa: Boolean,
    val pathLenConstraint: Int?,
    val keyUsage: BooleanArray?,
    val extendedKeyUsage: List<String>,
    val sanDns: List<String>,
    val sanIp: List<String>,
    val commonName: String?,
    val nameConstraints: NameConstraintsData,
    val sigAlgOid: String,
    val sigAlgName: String,
    val sigKeyFamily: String,    // RSA / ECDSA / Ed25519 / ...
    val sigHashFamily: String,   // SHA256 / SHA1 / ...
    val publicKeyFamily: String, // RSA / EC / Ed25519
    val publicKeyBits: Int,
    val notBefore: Instant,
    val notAfter: Instant,
    val isSelfSigned: Boolean
) {
    fun labeledName(): String = commonName?.takeIf { it.isNotBlank() } ?: subjectDn

    fun presentedDnsNames(): List<String> {
        val names = sanDns.toMutableList()
        val cn = commonName
        if (cn != null && names.none { it.equals(cn, ignoreCase = true) }) names.add(cn)
        return names
    }

    fun presentedIpNames(): List<String> = sanIp

    override fun equals(other: Any?): Boolean = other is CertInfo &&
        other.fingerprintSha256 == fingerprintSha256

    override fun hashCode(): Int = fingerprintSha256.hashCode()
}

object CertLoader {
    val provider: BouncyCastleProvider = BouncyCastleProvider()
    private val converter: JcaX509CertificateConverter =
        JcaX509CertificateConverter().setProvider(provider)

    fun fromDer(der: ByteArray, pem: String): CertInfo {
        val holder = X509CertificateHolder(der)
        val x509 = converter.getCertificate(holder)
        val ext: Extensions? = holder.extensions

        val akiExt = ext?.let { AuthorityKeyIdentifier.fromExtensions(it) }
        val skiExt = ext?.let { SubjectKeyIdentifier.fromExtensions(it) }
        val bcExt = ext?.let { BasicConstraints.fromExtensions(it) }
        val kuExt = ext?.let { KeyUsage.fromExtensions(it) }
        val ekuExt = ext?.let { ExtendedKeyUsage.fromExtensions(it) }
        val sanExt = ext?.let { GeneralNames.fromExtensions(it, Extension.subjectAlternativeName) }
        val ncExt = if (ext != null && ext.getExtension(Extension.nameConstraints) != null) {
            NameConstraints.getInstance(ext.getExtension(Extension.nameConstraints).parsedValue)
        } else null

        val keyUsage = kuExt?.let { ku ->
            // RFC 5280 位序：digitalSignature=bit0 ... decipherOnly=bit8；BC 常量按该序编码
            val masks = intArrayOf(128, 64, 32, 16, 8, 4, 2, 1, 0x8000)
            BooleanArray(9) { idx -> ku.hasUsages(masks[idx]) }
        }

        val eku = ekuExt?.usages?.map { it.id } ?: emptyList()

        val sanDns = mutableListOf<String>()
        val sanIp = mutableListOf<String>()
        sanExt?.names?.forEach { gn ->
            when (gn.tagNo) {
                GeneralName.dNSName -> sanDns.add(gn.name.toString())
                GeneralName.iPAddress -> decodeIp(gn)?.let { sanIp.add(it) }
            }
        }

        val ncData = if (ncExt != null) {
            NameConstraintsData(
                permitted = subtrees(ncExt.permittedSubtrees.toList()),
                excluded = subtrees(ncExt.excludedSubtrees.toList())
            )
        } else NameConstraintsData.NONE

        val sigOid = holder.signatureAlgorithm.algorithm
        val (sigName, sigKey, sigHash) = describeSignature(sigOid, holder)
        val (pkFamily, pkBits) = describePublicKey(holder)
        val derCopy = der.clone()

        return CertInfo(
            holder = holder,
            x509 = x509,
            der = derCopy,
            pem = pem,
            fingerprintSha256 = sha256Hex(derCopy),
            subjectDn = holder.subject.toString(),
            issuerDn = holder.issuer.toString(),
            subjectKeyId = skiExt?.keyIdentifier?.let { hex(it) },
            authorityKeyId = akiExt?.keyIdentifier?.let { hex(it) },
            basicConstraintsPresent = bcExt != null,
            isCa = bcExt?.isCA ?: false,
            pathLenConstraint = if (bcExt != null && bcExt.pathLenConstraint != null)
                bcExt.pathLenConstraint.intValueExact() else null,
            keyUsage = keyUsage,
            extendedKeyUsage = eku,
            sanDns = sanDns,
            sanIp = sanIp,
            commonName = firstRdn(holder.subject, BCStyle.CN),
            nameConstraints = ncData,
            sigAlgOid = sigOid.id,
            sigAlgName = sigName,
            sigKeyFamily = sigKey,
            sigHashFamily = sigHash,
            publicKeyFamily = pkFamily,
            publicKeyBits = pkBits,
            notBefore = holder.notBefore.toInstant(),
            notAfter = holder.notAfter.toInstant(),
            isSelfSigned = holder.issuer == holder.subject
        )
    }

    private fun subtrees(generalSubtrees: List<GeneralSubtree>): List<NameConstraint> {
        return generalSubtrees.mapNotNull { st ->
            val gn = st.base
            when (gn.tagNo) {
                GeneralName.dNSName -> NameConstraint("dns", gn.name.toString())
                GeneralName.directoryName -> NameConstraint("directory", X500Name.getInstance(gn.name).toString())
                GeneralName.iPAddress -> decodeIp(gn)?.let { NameConstraint("ip", it) }
                GeneralName.rfc822Name -> NameConstraint("email", gn.name.toString())
                else -> null
            }
        }
    }

    private fun decodeIp(gn: GeneralName): String? = runCatching {
        val obj = gn.name
        val octets: ByteArray = if (obj is org.bouncycastle.asn1.ASN1TaggedObject) {
            org.bouncycastle.asn1.ASN1OctetString.getInstance(obj, false).octets
        } else {
            org.bouncycastle.asn1.ASN1OctetString.getInstance(obj.toASN1Primitive()).octets
        }
        when {
            octets.size == 4 -> octets.joinToString(".") { (it.toInt() and 0xFF).toString() }
            octets.size == 16 -> java.net.InetAddress.getByAddress(octets).hostAddress
            else -> null
        }
    }.getOrNull()

    private fun firstRdn(name: X500Name, oid: ASN1ObjectIdentifier): String? {
        val rdns = name.getRDNs(oid)
        if (rdns.isEmpty()) return null
        val first = rdns.first().first
        return (first as? AttributeTypeAndValue)?.value?.toString()
    }

    private fun describeSignature(
        oid: ASN1ObjectIdentifier,
        holder: X509CertificateHolder
    ): Triple<String, String, String> {
        val name = when (oid) {
            PKCSObjectIdentifiers.sha1WithRSAEncryption -> "SHA1withRSA"
            PKCSObjectIdentifiers.sha224WithRSAEncryption -> "SHA224withRSA"
            PKCSObjectIdentifiers.sha256WithRSAEncryption -> "SHA256withRSA"
            PKCSObjectIdentifiers.sha384WithRSAEncryption -> "SHA384withRSA"
            PKCSObjectIdentifiers.sha512WithRSAEncryption -> "SHA512withRSA"
            X9ObjectIdentifiers.ecdsa_with_SHA1 -> "SHA1withECDSA"
            X9ObjectIdentifiers.ecdsa_with_SHA224 -> "SHA224withECDSA"
            X9ObjectIdentifiers.ecdsa_with_SHA256 -> "SHA256withECDSA"
            X9ObjectIdentifiers.ecdsa_with_SHA384 -> "SHA384withECDSA"
            X9ObjectIdentifiers.ecdsa_with_SHA512 -> "SHA512withECDSA"
            else -> holder.signatureAlgorithm.algorithm.id
        }
        val keyFamily = when {
            oid == PKCSObjectIdentifiers.id_RSASSA_PSS -> "RSA-PSS"
            name.endsWith("withRSA") -> "RSA"
            "ECDSA" in name || "EC" in name -> "ECDSA"
            name.contains("Ed25519") -> "Ed25519"
            name.contains("Ed448") -> "Ed448"
            else -> "UNKNOWN"
        }
        val hashFamily = when {
            oid == PKCSObjectIdentifiers.id_RSASSA_PSS -> pssHashName(holder)
            name.startsWith("SHA1") -> "SHA1"
            name.startsWith("SHA224") -> "SHA224"
            name.startsWith("SHA256") -> "SHA256"
            name.startsWith("SHA384") -> "SHA384"
            name.startsWith("SHA512") -> "SHA512"
            name.startsWith("MD5") -> "MD5"
            else -> "UNKNOWN"
        }
        return Triple(name, keyFamily, hashFamily)
    }

    private fun pssHashName(holder: X509CertificateHolder): String {
        return runCatching {
            val params = holder.signatureAlgorithm.parameters
            val pss = org.bouncycastle.asn1.pkcs.RSASSAPSSparams.getInstance(params)
            val oid = pss.hashAlgorithm.algorithm
            when (oid.id) {
                "2.16.840.1.101.3.4.2.1" -> "SHA256"
                "2.16.840.1.101.3.4.2.2" -> "SHA384"
                "2.16.840.1.101.3.4.2.3" -> "SHA512"
                else -> oid.id
            }
        }.getOrDefault("SHA256")
    }

    private fun describePublicKey(holder: X509CertificateHolder): Pair<String, Int> {
        val spki = holder.subjectPublicKeyInfo
        val algOid = spki.algorithm.algorithm.id
        return when {
            algOid == "1.2.840.113549.1.1.1" -> {
                val rsa = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(
                    org.bouncycastle.asn1.ASN1Primitive.fromByteArray(spki.publicKeyData.bytes)
                )
                "RSA" to rsa.modulus.bitLength()
            }
            algOid.startsWith("1.2.840.10045") -> {
                val q = java.security.KeyFactory.getInstance("EC")
                    .generatePublic(java.security.spec.X509EncodedKeySpec(spki.encoded))
                "EC" to (q as java.security.interfaces.ECPublicKey).params.curve.field.fieldSize
            }
            algOid == "1.3.101.112" -> "Ed25519" to 256
            algOid == "1.3.101.113" -> "Ed448" to 456
            else -> "UNKNOWN($algOid)" to 0
        }
    }

    fun sha256Hex(data: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(data))

    private val HEX = "0123456789abcdef".toCharArray()

    fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(HEX[(b.toInt() ushr 4) and 0xF])
            sb.append(HEX[b.toInt() and 0xF])
        }
        return sb.toString()
    }
}

object PemBlocks {
    data class Block(val label: String, val content: ByteArray, val index: Int)
    data class ParseResult(val blocks: List<Block>, val errors: List<String>)

    private val HEADER = Regex("-----BEGIN ([A-Z0-9 ]+)-----")
    private val FOOTER = Regex("-----END ([A-Z0-9 ]+)-----")

    fun parse(input: String): ParseResult {
        val errors = mutableListOf<String>()
        val blocks = mutableListOf<Block>()
        val matches = HEADER.findAll(input).toList()
        if (matches.isEmpty()) {
            return ParseResult(emptyList(), listOf("输入中没有找到 PEM 块（需要 -----BEGIN CERTIFICATE-----）"))
        }
        matches.forEachIndexed { idx, begin ->
            val label = begin.groupValues[1]
            val footerMatch = FOOTER.find(input, begin.range.last + 1)
            if (footerMatch == null || footerMatch.groupValues[1] != label) {
                errors += "第 ${idx + 1} 个 PEM 块（$label）缺少匹配的结束标记"
                return@forEachIndexed
            }
            val body = input.substring(begin.range.last + 1, footerMatch.range.first)
                .lines().joinToString("") { it.trim() }
            if (label != "CERTIFICATE") {
                if (label.contains("PRIVATE KEY")) {
                    errors += "第 ${idx + 1} 个 PEM 块是 $label：私钥材料已忽略，绝不写入导出"
                } else {
                    errors += "第 ${idx + 1} 个 PEM 块类型为 $label，不是证书，已跳过"
                }
                return@forEachIndexed
            }
            val der = runCatching { Base64.getDecoder().decode(body) }
                .getOrElse {
                    errors += "第 ${idx + 1} 个 PEM 块 Base64 解码失败：${it.message}"
                    return@forEachIndexed
                }
            blocks += Block(label, der, idx + 1)
        }
        return ParseResult(blocks, errors)
    }
}
