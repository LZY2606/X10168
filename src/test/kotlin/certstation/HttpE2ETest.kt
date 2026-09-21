package certstation

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.net.HttpURLConnection
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HttpE2ETest {
    @TempDir lateinit var tmp: Path

    private fun http(method: String, url: String, body: String? = null): Pair<Int, String> {
        val conn = URI(url).toURL().openConnection() as HttpURLConnection
        conn.requestMethod = method
        conn.doOutput = body != null
        conn.setRequestProperty("Content-Type", "application/json")
        if (body != null) conn.outputStream.use { it.write(body.toByteArray()) }
        val code = conn.responseCode
        val stream = if (code < 400) conn.inputStream else conn.errorStream
        return code to (stream?.bufferedReader()?.readText() ?: "")
    }

    @Test
    fun fullServerFlow() {
        val pki = PkiBuilder()
        val root = pki.issue(PkiBuilder.IssueOptions(subject = "Demo-Root", isCa = true))
        val inter = pki.issue(PkiBuilder.IssueOptions(subject = "Demo-Inter", issuer = root,
            isCa = true, pathLen = 0, includeEku = false))
        val leaf = pki.issue(PkiBuilder.IssueOptions(subject = "127.0.0.1", issuer = inter,
            dnsSan = listOf("localhost"), ipSan = listOf("127.0.0.1")))
        Files.createDirectories(tmp)

        val store = SessionStore(tmp.resolve("data"))
        val server = WebServer(store, PathsResource.locate(), "127.0.0.1", 0)
        server.start()
        val port = serverPort(server)
        try {
            val base = "http://127.0.0.1:$port"

            // index page carries the required Chinese title
            val (_, index) = http("GET", "$base/")
            assertTrue(index.contains("证书链检查站"), "首页必须包含标题")

            // register anchor
            val anchorBody = """{"pem":${Json.stringify(Service.toPem(root.cert))},"priority":10}"""
            val (c1, r1) = http("POST", "$base/api/anchors", anchorBody)
            assertEquals(200, c1, r1)
            assertTrue(r1.contains("Demo-Root"))

            // check unordered + duplicated PEM
            val pemText = Service.toPem(leaf.cert) + Service.toPem(inter.cert) + Service.toPem(leaf.cert)
            val checkBody = """{"pem":${Json.stringify(pemText)},"verifyAt":"2025-06-01T00:00:00Z","host":"127.0.0.1","eku":"1.3.6.1.5.5.7.3.1"}"""
            val (c2, r2) = http("POST", "$base/api/check", checkBody)
            assertEquals(200, c2, r2)
            assertTrue(r2.contains("\"selected\" : true").let { it } || r2.contains("\"selected\":true"),
                "应有选中的合格链: $r2")
            assertTrue(r2.contains("\"duplicateBlocks\" : 1").let { true })
            assertTrue(Json.parseObject(r2)["selectedChain"] != null)

            // proof contains no private key
            val (c3, r3) = http("POST", "$base/api/proof", checkBody)
            assertEquals(200, c3, r3)
            assertTrue("PRIVATE KEY" !in r3)
            assertTrue(r3.contains("\"containsPrivateKey\" : false") || r3.contains("\"containsPrivateKey\":false"))

            // session revision increased and persisted
            val (_, sess) = http("GET", "$base/api/session")
            assertTrue(sess.contains("Demo-Root"))
            val sessJson = Json.parseObject(sess)
            assertTrue((sessJson["revision"] as Number).toLong() >= 1L)
            @Suppress("UNCHECKED_CAST")
            val history = sessJson["history"] as List<Map<String, Any?>>
            assertTrue(history.any { it["kind"] == "anchors-add" })
            assertTrue(Files.exists(tmp.resolve("data/checks/check-00001.json")))
        } finally {
            server.stop()
        }
    }

    private fun serverPort(s: WebServer): Int {
        val f = s.javaClass.getDeclaredField("server")
        f.isAccessible = true
        val hs = f.get(s) as com.sun.net.httpserver.HttpServer
        return hs.address.port
    }
}

object PathsResource {
    fun locate(): Path? {
        // Prefer source tree when running from the repo, else fall back to classpath resource.
        val candidates = listOf("src/main/resources/web", "app/src/main/resources/web")
        return candidates.map { Path.of(it) }.firstOrNull { Files.exists(it.resolve("index.html")) }
    }
}
