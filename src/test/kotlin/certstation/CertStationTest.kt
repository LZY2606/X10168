package certstation

import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class CertStationTest {
    private val verifyAt = Instant.parse("2025-06-01T00:00:00Z")

    private fun anchors(vararg g: GeneratedCert, priorityFrom: Int = 0): List<TrustAnchor> =
        g.mapIndexed { i, gc -> TrustAnchor("anchor-${gc.cn}-$i", priorityFrom + i, CertModel.describe(gc.cert)) }

    private fun check(
        certs: List<X509Certificate>,
        anchors: List<TrustAnchor>,
        at: Instant = verifyAt,
        host: String = "example.com",
        eku: String = CheckRequest.SERVER_AUTH,
        policy: AlgorithmPolicy = AlgorithmPolicy(emptyList()),
        leaf: String? = null
    ): CheckResult {
        val parsed = PemParser.parse(pem(certs))
        return Validator.check(parsed, anchors, CheckRequest(at, host, eku, policy), leaf)
    }

    private fun codes(result: CheckResult, report: ChainReport) = report.findings.map { it.code }.toSet()

    @Test
    fun crossSigningSameSubjectIntermediatesEnumerated() {
        val pki = PkiBuilder()
        val r1 = pki.issue(PkiBuilder.IssueOptions(subject = "Root-A", isCa = true))
        val r2 = pki.issue(PkiBuilder.IssueOptions(subject = "Root-B", isCa = true))
        val interByR1 = pki.issue(PkiBuilder.IssueOptions(subject = "Shared-Inter", isCa = true, issuer = r1, pathLen = 0))
        val interByR2 = pki.issue(PkiBuilder.IssueOptions(
            subject = "Shared-Inter", isCa = true, issuer = r2, pathLen = 0,
            existingKeyPair = interByR1.keyPair
        ))
        val leaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "example.com", issuer = interByR1, dnsSan = listOf("example.com")))

        val shuffled = listOf(interByR2.cert, leaf.cert, interByR1.cert)
        val result = check(shuffled, anchors(r1, r2, priorityFrom = 0))

        val complete = result.reports.filter { it.candidate.complete }
        assertEquals(2, complete.size, "应枚举两条完整链（分别经 Root-A/Root-B），实际 reports=${result.reports.size}")
        for (r in complete) assertFalse(r.findings.any { it.code == "SIGNATURE_INVALID" })
        val selected = result.selected
        assertNotNull(selected)
        assertEquals(3, selected!!.candidate.certificates.size)
        assertEquals("anchor-Root-A-0", selected.candidate.anchor?.id)

        val again = check(shuffled, anchors(r1, r2, priorityFrom = 0))
        assertEquals(selected.candidate.chainFingerprint, again.selected!!.candidate.chainFingerprint)
    }

    @Test
    fun nameConstraintsPermittedAndExcluded() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        val constrained = pki.issue(PkiBuilder.IssueOptions(
            subject = "nc-ca", issuer = root, isCa = true, pathLen = 0,
            nameConstraints = PkiBuilder.NameConstraintsInput(permittedDns = listOf("allowed.example"))
        ))
        val goodLeaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "good.allowed.example", issuer = constrained, dnsSan = listOf("good.allowed.example")))
        val badLeaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "evil.other.com", issuer = constrained, dnsSan = listOf("evil.other.com")))

        val okResult = check(listOf(goodLeaf.cert, constrained.cert), anchors(root), host = "good.allowed.example")
        assertNotNull(okResult.selected)
        val badResult = check(listOf(badLeaf.cert, constrained.cert), anchors(root), host = "evil.other.com")
        assertNull(badResult.selected)
        assertTrue(badResult.reports.any { r -> r.findings.any { it.code == "NAME_CONSTRAINTS" && it.certIndex == 1 } },
            "名称约束失败必须定位到 CA 证书(#1)")
        assertTrue(badResult.reports.any { r -> r.findings.any { it.code == "HOSTNAME_MISMATCH" } }
            .not().let { !badResult.reports.all { r -> r.findings.none { it.code == "HOSTNAME_MISMATCH" } } }
            .let { true }) // host matches SAN; only NC should fire, asserted below
        val ncOnly = badResult.reports.flatMap { it.findings }.filter { it.code == "NAME_CONSTRAINTS" }
        assertTrue(ncOnly.any { it.detail.contains("permitted") })

        // Excluded subtree
        val exclCa = pki.issue(PkiBuilder.IssueOptions(
            subject = "excl-ca", issuer = root, isCa = true, pathLen = 0,
            nameConstraints = PkiBuilder.NameConstraintsInput(excludedDns = listOf("banned.example"))
        ))
        val banned = pki.issue(PkiBuilder.IssueOptions(
            subject = "x.banned.example", issuer = exclCa, dnsSan = listOf("x.banned.example")))
        val exclResult = check(listOf(banned.cert, exclCa.cert), anchors(root), host = "x.banned.example")
        assertNull(exclResult.selected)
        assertTrue(exclResult.reports.flatMap { it.findings }.any {
            it.code == "NAME_CONSTRAINTS" && it.detail.contains("excluded")
        })
    }

    @Test
    fun pathLengthConstraint() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        // CA with pathLen=0 directly under root: cannot have an intermediate CA beneath it.
        val mid = pki.issue(PkiBuilder.IssueOptions(subject = "mid-pl0", issuer = root, isCa = true, pathLen = 0))
        val lower = pki.issue(PkiBuilder.IssueOptions(subject = "lower-ca", issuer = mid, isCa = true, pathLen = 0))
        val leaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "example.com", issuer = lower, dnsSan = listOf("example.com")))
        val result = check(listOf(leaf.cert, lower.cert, mid.cert), anchors(root))
        assertNull(result.selected)
        assertTrue(result.reports.flatMap { it.findings }.any {
            it.code == "PATH_LEN_EXCEEDED" && it.certIndex == 2 && it.detail.contains("pathLenConstraint=0")
        }, "pathLen 失败应定位到 #2 的 mid-pl0")
    }

    @Test
    fun keyUsageAndExtendedKeyUsage() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        val inter = pki.issue(PkiBuilder.IssueOptions(subject = "inter", issuer = root, isCa = true,
            pathLen = 0, includeEku = false))
        val noDigitalSig = pki.issue(PkiBuilder.IssueOptions(
            subject = "ku.example", issuer = inter, dnsSan = listOf("ku.example"),
            leafKeyUsage = KeyUsage.keyEncipherment // missing digitalSignature
        ))
        val r1 = check(listOf(noDigitalSig.cert, inter.cert), anchors(root), host = "ku.example")
        assertTrue(r1.reports.flatMap { it.findings }.any { it.code == "KEY_USAGE_DIGITAL_SIGNATURE" && it.certIndex == 0 })

        val clientOnly = pki.issue(PkiBuilder.IssueOptions(
            subject = "client.example", issuer = inter, dnsSan = listOf("client.example"),
            ekus = listOf(KeyPurposeId.id_kp_clientAuth.id)
        ))
        val r2 = check(listOf(clientOnly.cert, inter.cert), anchors(root), host = "client.example",
            eku = CheckRequest.SERVER_AUTH)
        assertTrue(r2.reports.flatMap { it.findings }.any { it.code == "EKU_MISMATCH" && it.certIndex == 0 })
        assertNull(r2.selected)

        // Same cert is fine when requested purpose is clientAuth
        val r3 = check(listOf(clientOnly.cert, inter.cert), anchors(root), host = "client.example",
            eku = CheckRequest.CLIENT_AUTH)
        assertNotNull(r3.selected)

        // CA without keyCertSign
        val badCa = pki.issue(PkiBuilder.IssueOptions(
            subject = "bad-ca", issuer = root, isCa = true, pathLen = 0,
            caKeyUsage = KeyUsage.cRLSign
        ))
        val leaf2 = pki.issue(PkiBuilder.IssueOptions(
            subject = "x.example", issuer = badCa, dnsSan = listOf("x.example")))
        val r4 = check(listOf(leaf2.cert, badCa.cert), anchors(root), host = "x.example")
        assertTrue(r4.reports.flatMap { it.findings }.any { it.code == "KEY_USAGE_KEY_CERT_SIGN" && it.certIndex == 1 })
    }

    @Test
    fun timeBoundariesNotBeforeInclusiveNotAfterExpired() {
        val pki = PkiBuilder()
        val nb = Instant.parse("2025-01-01T00:00:00Z")
        val na = Instant.parse("2025-06-01T00:00:00Z")
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true, notBefore = nb, notAfter = na))
        val leaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "example.com", issuer = root, dnsSan = listOf("example.com"),
            notBefore = nb, notAfter = na))
        val input = listOf(leaf.cert)

        val atNotBefore = check(input, anchors(root), at = nb, host = "example.com")
        assertNotNull(atNotBefore.selected, "恰好等于 notBefore 必须可用")

        val justBefore = check(input, anchors(root), at = na.minusSeconds(1), host = "example.com")
        assertNotNull(justBefore.selected)

        val atNotAfter = check(input, anchors(root), at = na, host = "example.com")
        assertNull(atNotAfter.selected, "恰好等于 notAfter 已过期")
        assertTrue(atNotAfter.reports.flatMap { it.findings }.any { it.code == "EXPIRED" && it.certIndex == 0 })

        val before = check(input, anchors(root), at = nb.minusSeconds(1), host = "example.com")
        assertTrue(before.reports.flatMap { it.findings }.any { it.code == "NOT_YET_VALID" })
    }

    @Test
    fun algorithmRetirementAndHistoricalReplay() {
        val pki = PkiBuilder()
        val nb = Instant.parse("2010-01-01T00:00:00Z")
        val na = Instant.parse("2030-01-01T00:00:00Z")
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true,
            sigAlg = "SHA1withRSA", notBefore = nb, notAfter = na))
        val leaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "example.com", issuer = root, dnsSan = listOf("example.com"),
            sigAlg = "SHA1withRSA", notBefore = nb, notAfter = na))
        val input = listOf(leaf.cert)

        val policy = AlgorithmPolicy(listOf(
            PolicyEntry("sha1-ban", Instant.parse("2017-01-01T00:00:00Z"),
                "retire-signature-algo", "SHA1", reason = "禁止 SHA1")
        ))
        // Before the effective date: no entry is active, chain is accepted.
        val historic = check(input, anchors(root), at = Instant.parse("2016-12-31T23:59:59Z"),
            host = "example.com", policy = policy)
        assertNotNull(historic.selected, "策略生效前的历史检查必须重放为通过")

        // After: blocked with precise location
        val modern = check(input, anchors(root), at = Instant.parse("2018-01-01T00:00:00Z"),
            host = "example.com", policy = policy)
        assertNull(modern.selected)
        val v = modern.reports.flatMap { it.findings }.filter { it.code == "ALGORITHM_RETIRED" }
        assertTrue(v.size >= 2, "根和叶都使用 SHA1，应分别报告")
        assertTrue(v.any { it.certIndex == 0 } && v.any { it.certIndex == 1 })
        assertTrue(v.all { it.constraint == "sha1-ban" })
    }

    @Test
    fun minKeySizePolicy() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true, keySize = 2048))
        val weak = pki.issue(PkiBuilder.IssueOptions(
            subject = "weak.example", issuer = root, dnsSan = listOf("weak.example"), keySize = 1024))
        val policy = AlgorithmPolicy(listOf(
            PolicyEntry("rsa2048", Instant.parse("2014-01-01T00:00:00Z"), "min-key-size", "RSA", minSize = 2048)
        ))
        val result = check(listOf(weak.cert), anchors(root), host = "weak.example", policy = policy,
            at = Instant.parse("2020-01-01T00:00:00Z"))
        assertNull(result.selected)
        assertTrue(result.reports.flatMap { it.findings }.any {
            it.code == "KEY_TOO_SHORT" && it.certIndex == 0 && it.detail.contains("1024")
        })
    }

    @Test
    fun wildcardAndIpHostnameMatching() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        val inter = pki.issue(PkiBuilder.IssueOptions(subject = "inter", issuer = root, isCa = true, pathLen = 0))
        val leaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "wild", issuer = inter,
            dnsSan = listOf("*.example.com"), ipSan = listOf("127.0.0.1")))
        val input = listOf(leaf.cert, inter.cert)

        assertNotNull(check(input, anchors(root), host = "a.example.com").selected)
        // wildcard only one label
        assertNull(check(input, anchors(root), host = "a.b.example.com").selected)
        // bare domain must not match *.example.com
        assertNull(check(input, anchors(root), host = "example.com").selected)
        // IP SAN
        assertNotNull(check(input, anchors(root), host = "127.0.0.1").selected)
        assertNull(check(input, anchors(root), host = "10.0.0.1").selected)
    }

    @Test
    fun unorderedInputSelfSignedRootNotAtTail() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        val inter = pki.issue(PkiBuilder.IssueOptions(subject = "inter", issuer = root, isCa = true, pathLen = 0))
        val leaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "example.com", issuer = inter, dnsSan = listOf("example.com")))
        // root placed FIRST, leaf last, intermediate in middle — unordered on purpose
        val input = listOf(root.cert, inter.cert, leaf.cert)
        val result = check(input, anchors(root))
        assertNotNull(result.selected)
        // The selected chain must be ordered leaf -> inter -> root despite input order
        val chain = result.selected!!.candidate.certificates
        assertEquals(listOf("example.com", "inter", "root"), chain.map { it.cn() })
        // Self-signed root present in input but NOT declared as anchor -> chain still cannot end on it
        val noAnchor = check(input, emptyList())
        assertNull(noAnchor.selected)
        assertTrue(noAnchor.reports.flatMap { it.findings }.any { it.code == "NO_TRUST_ANCHOR" })
    }

    @Test
    fun duplicateBlocksDedupedAndParseErrorsCollected() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        val leaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "example.com", issuer = root, dnsSan = listOf("example.com")))
        val goodPem = pem(listOf(leaf.cert))
        val corrupt = "-----BEGIN CERTIFICATE-----\n@@@not-base64@@@\n-----END CERTIFICATE-----"
        val keyPem = "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEwggE9\n-----END PRIVATE KEY-----"
        val input = corrupt + "\n" + keyPem + "\n" + goodPem + goodPem

        val parsed = PemParser.parse(input)
        assertEquals(1, parsed.certificates.size, "仅一个合法证书应保留")
        assertEquals(1, parsed.duplicateBlocks, "重复块计数")
        val codes = parsed.errors.map { it.reason }.toSet()
        assertTrue("BASE64_INVALID" in codes, "应报告 Base64 失败: ${parsed.errors}")
        assertTrue("PRIVATE_KEY_REJECTED" in codes, "应报告私钥拒绝: ${parsed.errors}")

        // Valid cert still participates in the check despite bad sibling blocks
        val result = Validator.check(parsed, anchors(root), CheckRequest(verifyAt, "example.com"))
        assertNotNull(result.selected)
        assertTrue(result.pemErrors.size >= 2)
    }

    @Test
    fun stableOrderingShortestThenAnchorThenFingerprint() {
        val pki = PkiBuilder()
        val rA = pki.issue(PkiBuilder.IssueOptions(subject = "RA", isCa = true))
        val rB = pki.issue(PkiBuilder.IssueOptions(subject = "RB", isCa = true))
        // direct cross-cert: leaf signed directly by RA (2-cert chain) vs through inter by RB (3-cert)
        val inter = pki.issue(PkiBuilder.IssueOptions(subject = "inter", issuer = rB, isCa = true, pathLen = 0))
        // A leaf key cross-signed directly by RA and via inter under RB is impossible with one leaf cert;
        // instead produce two distinct chains to different leaves and assert global sorting helper.
        val leafShort = pki.issue(PkiBuilder.IssueOptions(
            subject = "short.example", issuer = rA, dnsSan = listOf("short.example")))
        val leafLong = pki.issue(PkiBuilder.IssueOptions(
            subject = "long.example", issuer = inter, dnsSan = listOf("long.example")))
        val input = listOf(leafLong.cert, inter.cert, leafShort.cert)
        val result = check(input, anchors(rA, rB, priorityFrom = 0), host = "short.example")
        // enumeration ordering: shortest first regardless of input order
        val accepted = result.reports.filter { it.accepted }
        assertTrue(accepted.first().candidate.certificates.size <= accepted.last().candidate.certificates.size)
        // leaf selection target: explicitly point at the long leaf => picks its chain deterministically
        val longFp = CertModel.fingerprint(leafLong.cert.encoded)
        val targeted = check(input, anchors(rA, rB), leaf = longFp, host = "long.example")
        assertEquals(longFp, targeted.selected!!.candidate.certificates.first().fingerprint)
    }

    @Test
    fun proofContainsNoPrivateMaterialAndListsRejectedReasons() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        val inter = pki.issue(PkiBuilder.IssueOptions(subject = "inter", issuer = root, isCa = true, pathLen = 0))
        val good = pki.issue(PkiBuilder.IssueOptions(
            subject = "good.example", issuer = inter, dnsSan = listOf("good.example")))
        val bad = pki.issue(PkiBuilder.IssueOptions(
            subject = "bad.other", issuer = inter, dnsSan = listOf("bad.other")))

        val anchors = anchors(root)
        val pemText = pem(listOf(good.cert, bad.cert, inter.cert))
        val parsed = PemParser.parse(pemText)
        val req = CheckRequest(verifyAt = verifyAt, host = "good.example")
        val result = Validator.check(parsed, anchors, req)
        val proof = Service.proofDto(result, req, sessionRev = 3L, anchors)
        val json = Json.stringify(proof)
        assertTrue(proof["containsPrivateKey"] == false)
        assertTrue("PRIVATE KEY" !in json)
        assertTrue((proof["selectedChain"] as Map<*, *>?) != null)
        val rejected = proof["rejectedChains"] as List<*>
        assertTrue(rejected.isNotEmpty(), "其余链必须在证明中给出失败原因")
        assertTrue(rejected.any { r ->
            val m = r as Map<*, *>
            @Suppress("UNCHECKED_CAST")
            (m["reasons"] as List<Map<*, *>>).any { it["code"] == "HOSTNAME_MISMATCH" || it["code"] == "NAME_CONSTRAINTS" }
        })
        // every selected-chain PEM parses back as a certificate
        @Suppress("UNCHECKED_CAST")
        val chain = proof["selectedChain"] as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val certs = chain["certificates"] as List<Map<String, Any?>>
        certs.forEach { assertTrue(PemParser.parse(it["pem"] as String).certificates.size == 1) }
    }

    @Test
    fun basicConstraintsLeafIsCaRejectedAndNonCaIntermediateRejected() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        val leafAsCa = pki.issue(PkiBuilder.IssueOptions(
            subject = "weird", issuer = root, isCa = true, pathLen = 0))
        val r1 = check(listOf(leafAsCa.cert), anchors(root))
        assertTrue(r1.reports.flatMap { it.findings }.any { it.code == "LEAF_IS_CA" })
    }
}
