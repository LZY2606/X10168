package checkpoint

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.GeneralSubtree
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.NameConstraints
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.time.Instant

data class GeneratedCert(
    val cert: X509Certificate,
    val keyPair: KeyPair,
    val subject: X500Name
) {
    fun pem(): String {
        val sw = StringWriter()
        JcaPEMWriter(sw).use { it.writeObject(cert) }
        return sw.toString()
    }
}

class PkiBuilder {
    private val bc = BouncyCastleProvider()
    private val extUtils = JcaX509ExtensionUtils()
    private var serial = BigInteger.valueOf(1)

    fun rsaKeyPair(bits: Int = 2048): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

    fun ecKeyPair(curve: String = "P-256"): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    data class IssueSpec(
        val subject: String,
        val keyPair: KeyPair,
        val issuer: GeneratedCert? = null,
        val notBefore: Instant = Instant.parse("2023-01-01T00:00:00Z"),
        val notAfter: Instant = Instant.parse("2030-01-01T00:00:00Z"),
        val ca: Boolean = false,
        val pathLen: Int? = null,
        val forceBasicConstraints: Boolean = false,
        val keyUsage: Int? = KeyUsage.digitalSignature or KeyUsage.keyEncipherment,
        val eku: List<KeyPurposeId>? = null,
        val dnsNames: List<String>? = null,
        val ipNames: List<String>? = null,
        val nameConstraints: NameConstraints? = null,
        val sigAlg: String = "SHA256withRSA",
        val ski: Boolean = true
    )

    fun issue(spec: IssueSpec): GeneratedCert {
        val issuerCert = spec.issuer
        val issuerName = issuerCert?.subject ?: X500Name(spec.subject)
        val subjectName = X500Name(spec.subject)
        val signerKey: PrivateKey = issuerCert?.keyPair?.private ?: spec.keyPair.private
        val builder = JcaX509v3CertificateBuilder(
            issuerName,
            serial++,
            Date.from(spec.notBefore),
            Date.from(spec.notAfter),
            subjectName,
            spec.keyPair.public
        )
        if (spec.ski) {
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(spec.keyPair.public))
        }
        val issuerPublicKey = issuerCert?.keyPair?.public
        if (issuerPublicKey != null) {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(issuerPublicKey))
        }
        if (spec.ca || spec.pathLen != null || spec.forceBasicConstraints) {
            val bcExt = when {
                spec.pathLen != null -> BasicConstraints(spec.pathLen)
                else -> BasicConstraints(spec.ca)
            }
            builder.addExtension(Extension.basicConstraints, true, bcExt)
        }
        spec.keyUsage?.let {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(it))
        }
        spec.eku?.let {
            builder.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(it.toTypedArray()))
        }
        if (spec.dnsNames != null || spec.ipNames != null) {
            val names = mutableListOf<GeneralName>()
            spec.dnsNames?.forEach { names += GeneralName(GeneralName.dNSName, it) }
            spec.ipNames?.forEach { names += GeneralName(GeneralName.iPAddress, it) }
            builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(names.toTypedArray()))
        }
        spec.nameConstraints?.let {
            builder.addExtension(Extension.nameConstraints, true, it)
        }
        val signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(spec.sigAlg)
            .setProvider(bc).build(signerKey)
        val holder = builder.build(signer)
        val cert = JcaX509CertificateConverter().setProvider(bc).getCertificate(holder)
        return GeneratedCert(cert, spec.keyPair, subjectName)
    }

    companion object {
        fun dnsConstraints(permitted: List<String> = emptyList(), excluded: List<String> = emptyList()): NameConstraints {
            val p = permitted.map { GeneralSubtree(GeneralName(GeneralName.dNSName, it)) }.toTypedArray()
            val e = excluded.map { GeneralSubtree(GeneralName(GeneralName.dNSName, it)) }.toTypedArray()
            return NameConstraints(p, e)
        }
    }
}

fun pemBundle(vararg certs: GeneratedCert): String = certs.joinToString("\n") { it.pem() }
fun certPems(vararg certs: GeneratedCert): List<String> = certs.map { it.pem() }
