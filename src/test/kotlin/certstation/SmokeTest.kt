package certstation

import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SmokeTest {
    @Test
    fun happyPath() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "root", isCa = true))
        val inter = pki.issue(PkiBuilder.IssueOptions(subject = "inter", issuer = root, isCa = true, pathLen = 0))
        val leaf = pki.issue(PkiBuilder.IssueOptions(
            subject = "example.com", issuer = inter,
            dnsSan = listOf("example.com", "www.example.com")
        ))

        val anchors = listOf(TrustAnchor("root", 0, CertModel.describe(root.cert)))
        val parsed = PemParser.parse(pem(listOf(leaf.cert, inter.cert)))
        val result = Validator.check(parsed, anchors, CheckRequest(
            verifyAt = Instant.parse("2025-06-01T00:00:00Z"),
            host = "www.example.com"
        ))
        println("candidates=${result.reports.size}")
        result.reports.forEach { r ->
            println("chain len=${r.candidate.certificates.size} accepted=${r.accepted} complete=${r.candidate.complete}")
            r.findings.forEach { println("  ${it.code} @${it.certIndex}: ${it.detail}") }
        }
        val selected = result.selected
        assertNotNull(selected)
        assertEquals(3, selected.candidate.certificates.size)
        assertTrue(selected.findings.isEmpty())
    }
}
