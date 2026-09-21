package checkpoint

import checkpoint.web.CheckpointHttpServer
import checkpoint.web.JsonParser
import checkpoint.web.JsonValue
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.net.HttpURLConnection
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

class HttpServerTest {
    companion object {
        private lateinit var server: CheckpointHttpServer
        private val client = HttpClient.newHttpClient()
        private var base = ""
        private const val PORT = 0

        @BeforeAll
        @JvmStatic
        fun up() {
            server = CheckpointHttpServer("127.0.0.1", 0)
            server.start()
            Thread.sleep(300)
            base = "http://127.0.0.1:${server.boundPort()}"
        }

        @JvmStatic
        fun base(): String = base

        @AfterAll
        @JvmStatic
        fun down() = server.stop()
    }

    @Test
    fun `index page title and check end to end through http`() {
        val page = client.send(
            HttpRequest.newBuilder(URI.create("${base}/")).build(),
            HttpResponse.BodyHandlers.ofString()
        )
        assertEquals(200, page.statusCode())
        assertTrue(page.body().contains("证书链检查站"))

        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueSpec("CN=WebRoot", pki.rsaKeyPair(), ca = true,
            keyUsage = KeyUsage.keyCertSign))
        val inter = pki.issue(PkiBuilder.IssueSpec("CN=WebInter", pki.rsaKeyPair(), issuer = root,
            ca = true, keyUsage = KeyUsage.keyCertSign))
        val leaf = pki.issue(PkiBuilder.IssueSpec("CN=web.example", pki.rsaKeyPair(), issuer = inter,
            eku = listOf(KeyPurposeId.id_kp_serverAuth), dnsNames = listOf("web.example")))

        val bodyMap = linkedMapOf<String, Any?>(
            "bundlePem" to (leaf.pem() + inter.pem()),
            "verifyAt" to "2024-06-01T12:00:00Z",
            "hostname" to "web.example",
            "purpose" to "serverAuth",
            "anchors" to listOf(mapOf("label" to "WebRoot", "pem" to root.pem())),
            "policy" to mapOf("versions" to listOf(mapOf(
                "version" to "v1",
                "effectiveAt" to "1970-01-01T00:00:00Z",
                "minKeyBitsRsa" to 2048,
                "minKeyBitsEc" to 224,
                "retiredAlgorithms" to mapOf("SHA1" to "2017-01-01T00:00:00Z")
            )))
        )
        val body = checkpoint.web.JsonWriter.render(bodyMap)

        val resp = client.send(
            HttpRequest.newBuilder(URI.create("${base}/api/check"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString()
        )
        assertEquals(200, resp.statusCode()) { resp.body() }
        val obj = JsonParser.parse(resp.body()) as JsonValue.Obj
        assertTrue(obj.value.containsKey("selectedChainIndex"))
        assertTrue(resp.body().contains("\"selected\":true"))
    }

}
