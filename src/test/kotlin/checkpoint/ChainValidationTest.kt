package checkpoint

import checkpoint.chain.CertificateReport
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ChainValidationTest {
    private val pki = PkiBuilder()

    private fun standardPki(): PkiSet {
        val rootKey = pki.rsaKeyPair()
        val root = pki.issue(
            PkiBuilder.IssueSpec("CN=TestRoot", rootKey, ca = true,
                keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign)
        )
        val inter = pki.issue(
            PkiBuilder.IssueSpec("CN=TestIntermediate", pki.rsaKeyPair(), issuer = root, ca = true,
                keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign)
        )
        val leaf = pki.issue(
            PkiBuilder.IssueSpec("CN=example.com", pki.rsaKeyPair(), issuer = inter,
                eku = listOf(KeyPurposeId.id_kp_serverAuth),
                dnsNames = listOf("example.com", "*.example.com"))
        )
        return PkiSet(root, inter, leaf)
    }

    data class PkiSet(val root: GeneratedCert, val inter: GeneratedCert, val leaf: GeneratedCert)

    @Test
    fun `happy path - ordered unordered bundle both accepted`() {
        val s = standardPki()
        val ordered = pemBundle(s.leaf, s.inter)
        val unordered = pemBundle(s.inter, s.leaf)
        val r1 = TestSupport.check(ordered, listOf("R1" to s.root))
        val r2 = TestSupport.check(unordered, listOf("R1" to s.root))
        assertNotNull(r1.selectedChainIndex)
        assertNotNull(r2.selectedChainIndex)
        assertEquals(3, r1.chains.single().length)
        assertEquals(listOf("leaf", "intermediate", "trust-anchor"),
            r1.chains.single().certificates.map { it.role })
    }

    @Test
    fun `self-signed root in bundle tail is not trusted unless explicit anchor`() {
        val s = standardPki()
        val withRoot = TestSupport.check(pemBundle(s.leaf, s.inter, s.root), emptyList())
        assertNull(withRoot.selectedChainIndex)
        assertTrue(withRoot.chains.any { it.terminal == "anchor_unreachable" })
        // 同一张根证书作为显式 anchor 后立即成功
        val explicit = TestSupport.check(pemBundle(s.leaf, s.inter), listOf("R1" to s.root))
        assertNotNull(explicit.selectedChainIndex)
    }

    @Test
    fun `cross signing enumerates both chains and selects via anchor priority`() {
        // 两套根，分别交叉签发两个同 subject 的中间证书
        val rootA = pki.issue(PkiBuilder.IssueSpec("CN=RootA", pki.rsaKeyPair(), ca = true,
            keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val rootB = pki.issue(PkiBuilder.IssueSpec("CN=RootB", pki.rsaKeyPair(), ca = true,
            keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val interA = pki.issue(PkiBuilder.IssueSpec("CN=SharedIntermediate", pki.rsaKeyPair(),
            issuer = rootA, ca = true, keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val interB = pki.issue(PkiBuilder.IssueSpec("CN=SharedIntermediate", pki.rsaKeyPair(),
            issuer = rootB, ca = true, keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=example.com", pki.rsaKeyPair(),
            issuer = interA, eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("example.com")))
        // interB 也签 leaf2；为让两条链共享叶子，用 interA 和 interB 各签同 subject 叶子
        val leafByB = pki.issue(PkiBuilder.IssueSpec("CN=example.com", pki.rsaKeyPair(),
            issuer = interB, eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("example.com")))
        val bundle = pemBundle(interA, interB, leaf, leafByB)

        val prioA = TestSupport.check(bundle, listOf("RootA" to rootA, "RootB" to rootB))
        val accepted = prioA.chains.filter { it.accepted }
        assertEquals(2, accepted.size)
        val selected = prioA.chains[prioA.selectedChainIndex!!]
        assertEquals("RootA", selected.anchorLabel)

        val prioB = TestSupport.check(bundle, listOf("RootB" to rootB, "RootA" to rootA))
        assertEquals("RootB", prioB.chains[prioB.selectedChainIndex!!].anchorLabel)
    }

    @Test
    fun `same subject intermediates - wrong signature chain rejected precisely`() {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=Root", pki.rsaKeyPair(), ca = true,
            keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val inter1 = pki.issue(PkiBuilder.IssueSpec("CN=Inter", pki.rsaKeyPair(), issuer = root,
            ca = true, keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val inter2 = pki.issue(PkiBuilder.IssueSpec("CN=Inter", pki.rsaKeyPair(), issuer = root,
            ca = true, keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=example.com", pki.rsaKeyPair(), issuer = inter1,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("example.com")))
        val report = TestSupport.check(pemBundle(leaf, inter1, inter2), listOf("R" to root))
        val selected = report.chains[report.selectedChainIndex!!]
        assertTrue(selected.certificates.any { c ->
            c.findings.any { it["code"] == "SIGNATURE_OK" }
        })
        // 至少一条失败链，且失败原因定位到叶子证书的签名
        val bad = report.chains.first { !it.accepted }
        assertTrue(bad.certificates[0].findings.any { it["code"] == "SIGNATURE_INVALID" })
        assertTrue(bad.rejectReasons.any { it.contains("SIGNATURE_INVALID") })
    }

    @Test
    fun `shortest chain wins - direct anchor versus via intermediate`() {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=Root", pki.rsaKeyPair(), ca = true,
            keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        // 直接由根签发的叶子
        val directLeaf = pki.issue(PkiBuilder.IssueSpec("CN=example.com", pki.rsaKeyPair(),
            issuer = root, eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("example.com")))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=Inter", pki.rsaKeyPair(), issuer = root,
            ca = true, keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val viaLeaf = pki.issue(PkiBuilder.IssueSpec("CN=other.com", pki.rsaKeyPair(),
            issuer = inter, eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("other.com")))
        val report = TestSupport.check(
            pemBundle(directLeaf, inter, viaLeaf), listOf("R" to root),
            host = "example.com"
        )
        // example.com 只有一条直接链，长度 2
        val selected = report.chains[report.selectedChainIndex!!]
        assertEquals(2, selected.length)
    }

    @Test
    fun `path length constraint violation located on offending CA`() {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=Root", pki.rsaKeyPair(), ca = true,
            keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val inter1 = pki.issue(PkiBuilder.IssueSpec("CN=I1", pki.rsaKeyPair(), issuer = root,
            ca = true, pathLen = 0, keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val inter2 = pki.issue(PkiBuilder.IssueSpec("CN=I2", pki.rsaKeyPair(), issuer = inter1,
            ca = true, keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=example.com", pki.rsaKeyPair(), issuer = inter2,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("example.com")))
        val report = TestSupport.check(pemBundle(leaf, inter1, inter2), listOf("R" to root))
        assertNull(report.selectedChainIndex)
        val chain = report.chains.single()
        // I1 是链上 index=2
        assertEquals("PATH_LENGTH_EXCEEDED",
            chain.certificates.first { it.subjectDn.contains("I1") }
                .findings.first { it["severity"] == "error" }["code"])
    }

    @Test
    fun `basic constraints - non-CA used as issuer rejected`() {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=Root", pki.rsaKeyPair(), ca = true,
            keyUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val fake = pki.issue(PkiBuilder.IssueSpec("CN=FakeInter", pki.rsaKeyPair(), issuer = root,
            ca = false, forceBasicConstraints = true,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("fake.test")))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=example.com", pki.rsaKeyPair(), issuer = fake,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("example.com")))
        val report = TestSupport.check(pemBundle(leaf, fake, root), listOf("R" to root))
        assertNull(report.selectedChainIndex)
        assertTrue(report.chains.single().certificates.first { it.subjectDn.contains("FakeInter") }
            .findings.any { it["code"] == "NOT_CA" })
    }

    @Test
    fun `key usage - leaf missing digitalSignature rejected for tls server when neither bit set`() {
        val s = standardPki()
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=ku.example", pki.rsaKeyPair(), issuer = s.inter,
            keyUsage = org.bouncycastle.asn1.x509.KeyUsage.cRLSign,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("ku.example")))
        val report = TestSupport.check(pemBundle(leaf), listOf("R" to s.root), host = "ku.example")
        assertNull(report.selectedChainIndex)
        assertTrue(report.chains.single().certificates[0].findings.any { it["code"] == "KEY_USAGE_TLS_SERVER" })
    }

    @Test
    fun `eku mismatch located on leaf with required and presented`() {
        val s = standardPki()
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=cs.example", pki.rsaKeyPair(), issuer = s.inter,
            eku = listOf(KeyPurposeId.id_kp_codeSigning), dnsNames = listOf("cs.example")))
        val report = TestSupport.check(pemBundle(leaf), listOf("R" to s.root), host = "cs.example",
            purpose = "serverAuth")
        assertNull(report.selectedChainIndex)
        val f = report.chains.single().certificates[0].findings.first { it["code"] == "EKU_MISMATCH" }
        assertTrue(f["message"]!!.contains("serverAuth"))
    }
}
