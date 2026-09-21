package checkpoint

import checkpoint.web.JsonParser
import checkpoint.web.JsonWriter
import checkpoint.web.ReportJson
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PolicyAndParsingTest {
    private val pki = PkiBuilder()

    private fun ncPki(): Triple<GeneratedCert, GeneratedCert, GeneratedCert> {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=NCRoot", pki.rsaKeyPair(), ca = true,
            keyUsage = KeyUsage.keyCertSign))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=NCInter", pki.rsaKeyPair(), issuer = root,
            ca = true, keyUsage = KeyUsage.keyCertSign,
            nameConstraints = PkiBuilder.dnsConstraints(permitted = listOf("allowed.test"))))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=host.allowed.test", pki.rsaKeyPair(),
            issuer = inter, eku = listOf(KeyPurposeId.id_kp_serverAuth),
            dnsNames = listOf("host.allowed.test")))
        return Triple(root, inter, leaf)
    }

    @Test
    fun `name constraints permit matching subtree`() {
        val (root, inter, leaf) = ncPki()
        val report = TestSupport.check(pemBundle(leaf, inter), listOf("R" to root),
            host = "host.allowed.test")
        assertNotNull(report.selectedChainIndex)
    }

    @Test
    fun `name constraints violation located on leaf with constraint text`() {
        val (root, inter, _) = ncPki()
        val badLeaf = pki.issue(PkiBuilder.IssueSpec("CN=evil.other.com", pki.rsaKeyPair(),
            issuer = inter, eku = listOf(KeyPurposeId.id_kp_serverAuth),
            dnsNames = listOf("evil.other.com")))
        val report = TestSupport.check(pemBundle(badLeaf, inter), listOf("R" to root),
            host = "evil.other.com")
        assertNull(report.selectedChainIndex)
        val f = report.chains.single().certificates[0].findings
            .first { it["code"] == "NAME_CONSTRAINTS_VIOLATION" }
        assertTrue(f["message"]!!.contains("allowed.test"))
        assertTrue(f["message"]!!.contains("evil.other.com"))
    }

    @Test
    fun `excluded subtree is rejected`() {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=R", pki.rsaKeyPair(), ca = true, keyUsage = KeyUsage.keyCertSign))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=I", pki.rsaKeyPair(), issuer = root, ca = true,
            keyUsage = KeyUsage.keyCertSign,
            nameConstraints = PkiBuilder.dnsConstraints(excluded = listOf("blocked.test"))))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=x.blocked.test", pki.rsaKeyPair(), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("x.blocked.test")))
        val report = TestSupport.check(pemBundle(leaf, inter), listOf("R" to root), host = "x.blocked.test")
        assertNull(report.selectedChainIndex)
        assertTrue(report.chains.single().certificates[0].findings
            .any { it["code"] == "NAME_CONSTRAINTS_VIOLATION" })
    }

    @Test
    fun `algorithm retired at boundary date - before ok on and after rejected`() {
        val nb = java.time.Instant.parse("2010-01-01T00:00:00Z")
        val na = java.time.Instant.parse("2030-01-01T00:00:00Z")
        val root = pki.issue(PkiBuilder.IssueSpec("CN=R", pki.rsaKeyPair(), ca = true,
            keyUsage = KeyUsage.keyCertSign, sigAlg = "SHA1withRSA", notBefore = nb, notAfter = na))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=I", pki.rsaKeyPair(), issuer = root, ca = true,
            keyUsage = KeyUsage.keyCertSign, sigAlg = "SHA1withRSA", notBefore = nb, notAfter = na))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=h.example", pki.rsaKeyPair(), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("h.example"),
            sigAlg = "SHA1withRSA", notBefore = nb, notAfter = na))
        val bundle = pemBundle(leaf, inter)
        val before = TestSupport.check(bundle, listOf("R" to root), at = "2016-12-31T23:59:59Z", host = "h.example")
        assertNotNull(before.selectedChainIndex)
        val on = TestSupport.check(bundle, listOf("R" to root), at = "2017-01-01T00:00:00Z", host = "h.example")
        assertNull(on.selectedChainIndex)
        assertTrue(on.chains.single().certificates[0].findings.any { it["code"] == "ALGORITHM_RETIRED" })
    }

    @Test
    fun `historical check replays policy version in effect then`() {
        val nb = java.time.Instant.parse("2014-01-01T00:00:00Z")
        val na = java.time.Instant.parse("2026-01-01T00:00:00Z")
        val root = pki.issue(PkiBuilder.IssueSpec("CN=R", pki.rsaKeyPair(1152), ca = true,
            keyUsage = KeyUsage.keyCertSign, notBefore = nb, notAfter = na))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=I", pki.rsaKeyPair(1152), issuer = root,
            ca = true, keyUsage = KeyUsage.keyCertSign, notBefore = nb, notAfter = na))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=h.example", pki.rsaKeyPair(1152), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("h.example"),
            notBefore = nb, notAfter = na))
        val bundle = pemBundle(leaf, inter)
        val old = TestSupport.check(bundle, listOf("R" to root), host = "h.example",
            at = "2018-06-01T00:00:00Z", policy = TestSupport.multiVersionPolicy())
        assertEquals("v-2015", old.policyVersionApplied)
        assertNotNull(old.selectedChainIndex)
        val modern = TestSupport.check(bundle, listOf("R" to root), host = "h.example",
            at = "2024-06-01T00:00:00Z", policy = TestSupport.multiVersionPolicy())
        assertEquals("v-2020", modern.policyVersionApplied)
        assertNull(modern.selectedChainIndex)
        assertTrue(modern.chains.single().certificates.any { c ->
            c.findings.any { it["code"] == "WEAK_KEY" }
        })
    }

    @Test
    fun `time endpoints - equal notBefore valid equal notAfter expired`() {
        val nb = java.time.Instant.parse("2024-01-01T00:00:00Z")
        val na = java.time.Instant.parse("2024-12-31T00:00:00Z")
        val root = pki.issue(PkiBuilder.IssueSpec("CN=R", pki.rsaKeyPair(), ca = true,
            keyUsage = KeyUsage.keyCertSign, notBefore = nb, notAfter = na))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=I", pki.rsaKeyPair(), issuer = root,
            ca = true, keyUsage = KeyUsage.keyCertSign, notBefore = nb, notAfter = na))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=e.example", pki.rsaKeyPair(), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("e.example"),
            notBefore = nb, notAfter = na))
        val bundle = pemBundle(leaf, inter)
        assertNotNull(TestSupport.check(bundle, listOf("R" to root),
            at = "2024-01-01T00:00:00Z", host = "e.example").selectedChainIndex)
        val expired = TestSupport.check(bundle, listOf("R" to root),
            at = "2024-12-31T00:00:00Z", host = "e.example")
        assertNull(expired.selectedChainIndex)
        assertTrue(expired.chains.single().certificates[0].findings.any { it["code"] == "EXPIRED" })
        val notYet = TestSupport.check(bundle, listOf("R" to root),
            at = "2023-12-31T23:59:59Z", host = "e.example")
        assertTrue(notYet.chains.single().certificates[0].findings.any { it["code"] == "NOT_YET_VALID" })
    }

    @Test
    fun `duplicate blocks deduplicated and malformed pem does not stop others`() {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=R", pki.rsaKeyPair(), ca = true, keyUsage = KeyUsage.keyCertSign))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=I", pki.rsaKeyPair(), issuer = root, ca = true,
            keyUsage = KeyUsage.keyCertSign))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=d.example", pki.rsaKeyPair(), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("d.example")))
        val garbage = "-----BEGIN CERTIFICATE-----\n@@@notbase64@@@\n-----END CERTIFICATE-----"
        val privateKey = "-----BEGIN PRIVATE KEY-----\nYWJjZGVm\n-----END PRIVATE KEY-----"
        val bundle = listOf(garbage, leaf.pem(), inter.pem(), leaf.pem(), privateKey)
            .joinToString("\n")
        val report = TestSupport.check(bundle, listOf("R" to root), host = "d.example")
        assertNotNull(report.selectedChainIndex)
        assertEquals(1, report.duplicateFingerprints.size)
        assertTrue(report.parseErrors.any { it.contains("Base64 解码失败") })
        assertTrue(report.parseErrors.any { it.contains("私钥") })
    }

    @Test
    fun `stable selection across input permutations`() {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=R", pki.rsaKeyPair(), ca = true, keyUsage = KeyUsage.keyCertSign))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=I", pki.rsaKeyPair(), issuer = root, ca = true,
            keyUsage = KeyUsage.keyCertSign))
        val leafA = pki.issue(PkiBuilder.IssueSpec("CN=a.example", pki.rsaKeyPair(), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("a.example")))
        val leafB = pki.issue(PkiBuilder.IssueSpec("CN=b.example", pki.rsaKeyPair(), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("b.example")))
        val r1 = TestSupport.check(pemBundle(leafA, leafB, inter), listOf("R" to root), host = null)
        val r2 = TestSupport.check(pemBundle(leafB, inter, leafA), listOf("R" to root), host = null)
        val s1 = r1.chains[r1.selectedChainIndex!!].fingerprint
        val s2 = r2.chains[r2.selectedChainIndex!!].fingerprint
        // 无主机名时两张叶子各自一条合格链；排序必须稳定（同为长度3、同anchor，按指纹）
        assertEquals(s1, s2)
    }

    @Test
    fun `proof json contains no private key material and round-trips`() {
        val root = pki.issue(PkiBuilder.IssueSpec("CN=R", pki.rsaKeyPair(), ca = true, keyUsage = KeyUsage.keyCertSign))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=I", pki.rsaKeyPair(), issuer = root, ca = true,
            keyUsage = KeyUsage.keyCertSign))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=p.example", pki.rsaKeyPair(), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("p.example")))
        val report = TestSupport.check(pemBundle(leaf, inter), listOf("R" to root), host = "p.example")
        val policy = TestSupport.policy()
        val proof = ReportJson.toProofMap(report, pemBundle(leaf, inter),
            mapOf("versions" to policy.versions.map { it.version }))
        val text = JsonWriter.render(proof)
        assertFalse(text.contains("PRIVATE KEY"))
        assertTrue(text.contains("BEGIN CERTIFICATE"))
        val parsed = JsonParser.parse(text)
        assertNotNull(parsed)
        assertEquals(false, (parsed as checkpoint.web.JsonValue.Obj).value["containsPrivateKeys"]?.let {
            (it as checkpoint.web.JsonValue.Bool).value
        })
    }
}
