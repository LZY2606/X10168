package checkpoint.web

import checkpoint.chain.AnchorInput
import checkpoint.chain.CheckService
import checkpoint.model.PolicyVersion
import checkpoint.model.PolicySet
import checkpoint.model.TimeUtil
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.time.Instant

class CheckpointHttpServer(private val host: String, private val port: Int) {
    private val store = SessionStore()
    private val service = CheckService()
    private lateinit var server: HttpServer

    fun start() {
        server = HttpServer.create(InetSocketAddress(host, port), 0)
        server.createContext("/", ::handle)
        server.executor = java.util.concurrent.Executors.newFixedThreadPool(4)
        server.start()
        println("证书链检查站已启动: http://$host:$port （离线；不访问系统信任库，不发起任何网络请求）")
    }

    fun stop() = server.stop(0)

    fun boundPort(): Int = server.address.port

    private fun handle(ex: HttpExchange) {
        try {
            route(ex)
        } catch (e: Exception) {
            sendJson(ex, 400, mapOf("error" to (e.message ?: e.javaClass.simpleName)))
        }
    }

    private fun route(ex: HttpExchange) {
        val path = ex.requestURI.path
        when {
            path == "/" || path == "/index.html" -> serveIndex(ex)
            path == "/api/check" && ex.requestMethod == "POST" -> doCheck(ex, proof = false)
            path == "/api/proof" && ex.requestMethod == "POST" -> doCheck(ex, proof = true)
            path.startsWith("/api/session/") && ex.requestMethod == "GET" -> doGetSession(ex, path)
            path == "/api/health" -> sendJson(ex, 200, mapOf("status" to "ok", "offline" to true))
            else -> sendJson(ex, 404, mapOf("error" to "not found: $path"))
        }
    }

    private fun serveIndex(ex: HttpExchange) {
        val html = CheckpointHttpServer::class.java.getResourceAsStream("/web/index.html")
            ?.readBytes()
            ?: error("index.html 未找到")
        ex.responseHeaders.add("Content-Type", "text/html; charset=utf-8")
        ex.sendResponseHeaders(200, html.size.toLong())
        ex.responseBody.use { it.write(html) }
    }

    private fun doGetSession(ex: HttpExchange, path: String) {
        val parts = path.removePrefix("/api/session/").split("?").first().split("/")
        val id = parts.getOrNull(0)
        val version = parts.getOrNull(1)?.toIntOrNull()
        val session = id?.let { store.get(it) }
            ?: return sendJson(ex, 404, mapOf("error" to "会话不存在"))
        val snap = store.snapshot(session, version)
            ?: return sendJson(ex, 404, mapOf("error" to "版本不存在"))
        sendJson(ex, 200, linkedMapOf(
            "sessionId" to session.id,
            "currentVersion" to session.currentVersion,
            "version" to snap.version,
            "createdAt" to snap.createdAt.toString(),
            "anchors" to snap.anchors.mapIndexed { i, a ->
                mapOf("label" to (a.label ?: "anchor-$i"), "pem" to a.pem)
            },
            "policy" to policyToJson(snap.policy)
        ))
    }

    private fun doCheck(ex: HttpExchange, proof: Boolean) {
        val body = ex.requestBody.readBytes().toString(StandardCharsets.UTF_8)
        val root = JsonParser.parse(body) as? JsonValue.Obj
            ?: error("请求体必须是 JSON 对象")
        val map = root.value

        val bundle = str(map, "bundlePem") ?: ""
        val hostname = str(map, "hostname")
        val purpose = str(map, "purpose")
        val verifyAt = str(map, "verifyAt")
            ?: error("缺少 verifyAt（ISO-8601 UTC，例如 2024-06-01T12:00:00Z）")

        val anchors = mutableListOf<AnchorInput>()
        (map["anchors"] as? JsonValue.Arr)?.value?.forEach { item ->
            val obj = item as? JsonValue.Obj ?: return@forEach
            anchors += AnchorInput(str(obj.value, "label"), str(obj.value, "pem") ?: "")
        }

        val policy = parsePolicy((map["policy"] as? JsonValue.Obj)?.value)
        val sessionId = str(map, "sessionId")

        val session = store.getOrCreate(sessionId, anchors, policy)
        val input = checkpoint.chain.CheckInput(
            bundlePem = bundle,
            anchors = session.snapshots.last().anchors,
            hostname = hostname,
            purpose = purpose,
            verifyAtText = verifyAt,
            policy = session.snapshots.last().policy
        )
        val report = service.check(input, session.id, session.currentVersion)
        store.storeReport(session, report)

        val response = if (proof) {
            ReportJson.toProofMap(report, bundle, policyToJson(policy))
        } else {
            ReportJson.toMap(report)
        }
        sendJson(ex, 200, response)
    }

    private fun parsePolicy(map: Map<String, JsonValue>?): PolicySet {
        if (map == null) return PolicySet(defaultPolicy())
        val versionsArr = (map["versions"] as? JsonValue.Arr)?.value
            ?: return PolicySet(defaultPolicy())
        val versions = versionsArr.map { item ->
            val obj = item as? JsonValue.Obj ?: error("policy.versions 元素必须是对象")
            val v = obj.value
            val version = str(v, "version") ?: error("策略版本缺少 version")
            val effectiveAt = str(v, "effectiveAt")?.let(TimeUtil::parseInstant)
                ?: Instant.parse("1970-01-01T00:00:00Z")
            val retired = linkedMapOf<String, Instant>()
            (v["retiredAlgorithms"] as? JsonValue.Obj)?.value?.forEach { (k, value) ->
                val date = (value as? JsonValue.Str)?.value
                    ?: error("retiredAlgorithms.$k 必须是 ISO-8601 时间")
                retired[k.uppercase()] = TimeUtil.parseInstant(date)
            }
            PolicyVersion(
                version = version,
                effectiveAt = effectiveAt,
                minKeyBitsRsa = int(v, "minKeyBitsRsa") ?: 2048,
                minKeyBitsEc = int(v, "minKeyBitsEc") ?: 224,
                retiredAlgorithms = retired
            )
        }.sortedBy { it.effectiveAt }
        require(versions.isNotEmpty()) { "policy.versions 不能为空" }
        return PolicySet(versions)
    }

    private fun defaultPolicy(): List<PolicyVersion> = listOf(
        PolicyVersion(
            version = "default-2026",
            effectiveAt = Instant.parse("1970-01-01T00:00:00Z"),
            minKeyBitsRsa = 2048,
            minKeyBitsEc = 224,
            retiredAlgorithms = mapOf(
                "SHA1" to Instant.parse("2017-01-01T00:00:00Z"),
                "MD5" to Instant.parse("2005-01-01T00:00:00Z")
            )
        )
    )

    private fun policyToJson(policy: PolicySet): Map<String, Any?> = linkedMapOf(
        "versions" to policy.versions.map {
            linkedMapOf(
                "version" to it.version,
                "effectiveAt" to it.effectiveAt.toString(),
                "minKeyBitsRsa" to it.minKeyBitsRsa,
                "minKeyBitsEc" to it.minKeyBitsEc,
                "retiredAlgorithms" to it.retiredAlgorithms.mapValues { (_, v) -> v.toString() }
            )
        }
    )

    private fun str(map: Map<String, JsonValue>, key: String): String? =
        (map[key] as? JsonValue.Str)?.value

    private fun int(map: Map<String, JsonValue>, key: String): Int? =
        (map[key] as? JsonValue.Num)?.value?.intValueExact()

    private fun sendJson(ex: HttpExchange, status: Int, payload: Any?) {
        val bytes = JsonWriter.render(payload).toByteArray(StandardCharsets.UTF_8)
        ex.responseHeaders.add("Content-Type", "application/json; charset=utf-8")
        ex.sendResponseHeaders(status, bytes.size.toLong())
        ex.responseBody.use { it.write(bytes) }
    }
}
