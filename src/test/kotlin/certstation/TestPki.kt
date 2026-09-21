package certstation

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName as BcGeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.NameConstraints as BcNameConstraints
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

class GeneratedCert(val cert: X509Certificate, val keyPair: KeyPair, val cn: String)

class PkiBuilder {
    init {
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    }

    private var serialCounter = 1L
    private val extUtils = JcaX509ExtensionUtils()

    data class NameConstraintsInput(
        val permittedDns: List<String> = emptyList(),
        val excludedDns: List<String> = emptyList()
    )

    data class IssueOptions(
        val subject: String,
        val issuer: GeneratedCert? = null, // null => self-signed
        val isCa: Boolean = false,
        val pathLen: Int? = null,
        val dnsSan: List<String> = emptyList(),
        val ipSan: List<String> = emptyList(),
        val keySize: Int = 2048,
        val keyAlg: String = "RSA",
        val sigAlg: String = "SHA256withRSA",
        val leafKeyUsage: Int = KeyUsage.digitalSignature or KeyUsage.keyEncipherment,
        val caKeyUsage: Int = KeyUsage.keyCertSign or KeyUsage.cRLSign,
        val ekus: List<String> = listOf(KeyPurposeId.id_kp_serverAuth.id),
        val includeEku: Boolean = true,
        val nameConstraints: NameConstraintsInput? = null,
        val notBefore: Instant = Instant.parse("2020-01-01T00:00:00Z"),
        val notAfter: Instant = Instant.parse("2030-01-01T00:00:00Z"),
        val includeAki: Boolean = true,
        val includeSki: Boolean = true,
        val existingKeyPair: KeyPair? = null
    )

    fun issue(opts: IssueOptions): GeneratedCert {
        val kp = opts.existingKeyPair ?: generateKeyPair(opts.keyAlg, opts.keySize)
        val signer: GeneratedCert = opts.issuer ?: selfSignedShell(opts, kp)
        val signingKey: PrivateKey = opts.issuer?.keyPair?.private ?: kp.private

        val subjectName = X500Name("CN=${opts.subject}")
        val issuerName = X500Name("CN=${signer.cn}")
        val builder = JcaX509v3CertificateBuilder(
            issuerName,
            BigInteger.valueOf(serialCounter++),
            Date.from(opts.notBefore),
            Date.from(opts.notAfter),
            subjectName,
            kp.public
        )
        if (opts.includeSki) {
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(kp.public))
        }
        if (opts.issuer != null && opts.includeAki) {
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(signer.cert.publicKey))
        }
        if (opts.isCa) {
            builder.addExtension(Extension.basicConstraints, true,
                if (opts.pathLen != null) BasicConstraints(opts.pathLen) else BasicConstraints(true))
            builder.addExtension(Extension.keyUsage, true, KeyUsage(opts.caKeyUsage))
        } else {
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            builder.addExtension(Extension.keyUsage, true, KeyUsage(opts.leafKeyUsage))
        }
        if (opts.includeEku && opts.ekus.isNotEmpty()) {
            val purposes = opts.ekus.map { KeyPurposeId.getInstance(ASN1ObjectIdentifier(it)) }.toTypedArray()
            builder.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(purposes))
        }
        val sanNames = ArrayList<BcGeneralName>()
        opts.dnsSan.forEach { sanNames += BcGeneralName(BcGeneralName.dNSName, it) }
        opts.ipSan.forEach { sanNames += BcGeneralName(BcGeneralName.iPAddress, it) }
        if (sanNames.isNotEmpty()) {
            builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(sanNames.toTypedArray()))
        }
        opts.nameConstraints?.let { nc ->
            val tagged = ArrayList<org.bouncycastle.asn1.ASN1Encodable>()
            if (nc.permittedDns.isNotEmpty()) {
                val subtrees = DERSequence(nc.permittedDns.map {
                    DERSequence(BcGeneralName(BcGeneralName.dNSName, it))
                }.toTypedArray())
                tagged += DERTaggedObject(false, 0, subtrees)
            }
            if (nc.excludedDns.isNotEmpty()) {
                val subtrees = DERSequence(nc.excludedDns.map {
                    DERSequence(BcGeneralName(BcGeneralName.dNSName, it))
                }.toTypedArray())
                tagged += DERTaggedObject(false, 1, subtrees)
            }
            builder.addExtension(Extension.nameConstraints, true,
                BcNameConstraints.getInstance(DERSequence(tagged.toTypedArray())))
        }

        val signerBuilder = JcaContentSignerBuilder(opts.sigAlg).setProvider("BC").build(signingKey)
        val holder = builder.build(signerBuilder)
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(holder)
        return GeneratedCert(cert, kp, opts.subject)
    }

    private fun selfSignedShell(opts: IssueOptions, kp: KeyPair): GeneratedCert {
        // A lightweight self-signed cert carrying the new key, used solely so AKI/SKI
        // extension helpers have a public-key holder; for a real root this IS the cert.
        val shellOptions = opts.copy(issuer = null, nameConstraints = null)
        val name = X500Name("CN=${opts.subject}")
        val builder = JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(serialCounter++),
            Date.from(opts.notBefore), Date.from(opts.notAfter), name, kp.public
        )
        if (opts.includeSki) builder.addExtension(Extension.subjectKeyIdentifier, false,
            extUtils.createSubjectKeyIdentifier(kp.public))
        if (opts.isCa) builder.addExtension(Extension.basicConstraints, true,
            if (opts.pathLen != null) BasicConstraints(opts.pathLen) else BasicConstraints(true))
        val cs = JcaContentSignerBuilder(shellOptions.sigAlg).setProvider("BC").build(kp.private)
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(cs))
        return GeneratedCert(cert, kp, opts.subject)
    }

    private fun generateKeyPair(alg: String, size: Int): KeyPair {
        val gen = KeyPairGenerator.getInstance(alg)
        when (alg) {
            "RSA" -> gen.initialize(size)
            "EC" -> gen.initialize(java.security.spec.ECGenParameterSpec(when (size) {
                384 -> "secp384r1"; 521 -> "secp521r1"; else -> "secp256r1"
            }))
        }
        return gen.generateKeyPair()
    }
}

fun pem(cert: X509Certificate): String = Service.toPem(cert)
fun pem(certs: List<X509Certificate>): String = certs.joinToString("") { Service.toPem(it) }
