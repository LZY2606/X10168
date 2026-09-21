package certstation

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.time.Instant

class WebServer(
    private val store: SessionStore,
    private val webRoot: Path?,
    host: String,
    port: Int
) {
    private val server: HttpServer = HttpServer.create(InetSocketAddress(host, port), 0)

    init {
        server.createContext("/", guarded(::root))
        server.createContext("/api/session", guarded(::session))
        server.createContext("/api/anchors", guarded(::anchors))
        server.createContext("/api/policy", guarded(::policy))
        server.createContext("/api/check", guarded { check(it, proof = false) })
        server.createContext("/api/proof", guarded { check(it, proof = true) })
        server.executor = java.util.concurrent.Executors.newFixedThreadPool(4)
    }

    fun start() {
        server.start()
        val shownHost = server.address.hostString.ifEmpty { "0.0.0.0" }
        println("证书链检查站 已启动: http://$shownHost:${server.address.port}")
    }

    fun stop() = server.stop(0)

    private fun root(ex: HttpExchange) {
        val path = ex.requestURI.path
        if (path == "/") {
            serveStatic(ex, "index.html", "text/html; charset=utf-8")
            return
        }
        // Only whitelisted static assets are served.
        if (path in setOf("/app.js")) {
            serveStatic(ex, path.removePrefix("/"), "application/javascript; charset=utf-8")
            return
        }
        respond(ex, 404, mapOf("error" to "not found"))
    }

    private fun serveStatic(ex: HttpExchange, name: String, contentType: String) {
        val bytes = webRoot?.resolve(name)?.takeIf { java.nio.file.Files.exists(it) }
            ?.let { java.nio.file.Files.readAllBytes(it) }
            ?: javaClass.getResourceAsStream("/web/$name")?.use { it.readAllBytes() }
        if (bytes == null) { respond(ex, 404, mapOf("error" to "$name missing")); return }
        ex.responseHeaders.add("Content-Type", contentType)
        ex.sendResponseHeaders(200, bytes.size.toLong())
        ex.responseBody.use { it.write(bytes) }
    }

    private fun session(ex: HttpExchange) {
        val s = store.session
        respond(ex, 200, linkedMapOf(
            "id" to s.id,
            "revision" to s.revision,
            "anchors" to s.anchors.values.map {
                linkedMapOf(
                    "id" to it.id, "fingerprint" to it.fingerprint,
                    "subject" to it.subject, "priority" to it.priority,
                    "addedAt" to it.addedAt.toString()
                )
            },
            "policyEntries" to s.policyEntries.map {
                linkedMapOf("id" to it.id, "effectiveAt" to it.effectiveAt.toString(),
                    "kind" to it.kind, "target" to it.target, "minSize" to it.minSize, "reason" to it.reason)
            },
            "history" to s.history.map {
                linkedMapOf("revision" to it.revision, "at" to it.at.toString(),
                    "kind" to it.kind, "summary" to it.summary)
            }
        ))
    }

    private fun anchors(ex: HttpExchange) {
        when (ex.requestMethod) {
            "POST" -> {
                val body = body(ex)
                val pem = body.str("pem")
                val priority = (body["priority"] as? Number)?.toInt() ?: 100
                val parsed = PemParser.parse(pem)
                if (parsed.certificates.isEmpty()) {
                    respond(ex, 400, linkedMapOf("error" to "无可导入的证书", "pemErrors" to
                        parsed.errors.map { linkedMapOf("blockIndex" to it.blockIndex, "code" to it.reason, "message" to it.message) }))
                    return
                }
                val added = store.mutate("anchors-add", mapOf("count" to parsed.certificates.size)) { s ->
                    parsed.certificates.mapIndexed { i, cert ->
                        val info = CertModel.describe(cert)
                        val existing = s.anchors.values.firstOrNull { it.fingerprint == info.fingerprint }
                        if (existing != null) {
                            existing
                        } else {
                            val base = body.str("id").ifBlank { "anchor-" + info.fingerprint.substring(8, 16) }
                            val rec = AnchorRecord(
                                id = uniqueAnchorId(s, base),
                                pem = Service.toPem(cert),
                                fingerprint = info.fingerprint,
                                subject = info.subjectDn,
                                priority = priority + i,
                                addedAt = Instant.now()
                            )
                            s.anchors[rec.id] = rec
                            rec
                        }
                    }
                }
                respond(ex, 200, linkedMapOf("revision" to store.session.revision,
                    "anchors" to added.map { linkedMapOf(
                        "id" to it.id, "fingerprint" to it.fingerprint, "subject" to it.subject, "priority" to it.priority) }))
            }
            "DELETE" -> {
                val id = queryParam(ex, "id") ?: body(ex).str("id")
                store.mutate("anchors-remove", mapOf("id" to id)) { it.anchors.remove(id) }
                respond(ex, 200, mapOf("revision" to store.session.revision))
            }
            else -> respond(ex, 405, mapOf("error" to "method not allowed"))
        }
    }

    private fun uniqueAnchorId(s: Session, wanted: String): String {
        if (wanted !in s.anchors) return wanted
        var n = 2
        while ("$wanted-$n" in s.anchors) n++
        return "$wanted-$n"
    }

    private fun policy(ex: HttpExchange) {
        when (ex.requestMethod) {
            "POST" -> {
                val body = body(ex)
                val entry = PolicyEntry(
                    id = body.str("id").ifBlank { "policy-" + System.nanoTime() },
                    effectiveAt = Instant.parse(body.str("effectiveAt").ifBlank { Instant.now().toString() }),
                    kind = body.str("kind"),
                    target = body.str("target"),
                    minSize = (body["minSize"] as? Number)?.toInt() ?: 0,
                    reason = body.str("reason")
                )
                require(entry.kind in setOf("retire-signature-algo", "min-key-size")) { "未知策略类型" }
                store.mutate("policy-add", mapOf("id" to entry.id)) { it.policyEntries.add(entry) }
                respond(ex, 200, mapOf("revision" to store.session.revision, "entry" to mapOf(
                    "id" to entry.id, "effectiveAt" to entry.effectiveAt.toString(), "kind" to entry.kind,
                    "target" to entry.target, "minSize" to entry.minSize, "reason" to entry.reason)))
            }
            "DELETE" -> {
                val id = queryParam(ex, "id") ?: body(ex).str("id")
                store.mutate("policy-remove", mapOf("id" to id)) { s ->
                    s.policyEntries.removeAll { it.id == id }
                }
                respond(ex, 200, mapOf("revision" to store.session.revision))
            }
            else -> respond(ex, 405, mapOf("error" to "method not allowed"))
        }
    }

    private fun buildAnchors(): List<TrustAnchor> =
        store.session.anchors.values.sortedWith(compareBy({ it.priority }, { it.id })).mapNotNull { rec ->
            PemParser.parse(rec.pem).certificates.firstOrNull()?.let {
                TrustAnchor(rec.id, rec.priority, CertModel.describe(it))
            }
        }

    private fun check(ex: HttpExchange, proof: Boolean) {
        val body = body(ex)
        val pemText = body.str("pem")
        val verifyAt = Instant.parse(body.str("verifyAt").ifBlank { Instant.now().toString() })
        val host = body.str("host")
        val eku = body.str("eku").ifBlank { CheckRequest.SERVER_AUTH }
        val leaf = body.str("leafFingerprint").ifBlank { null }
        val anchors = buildAnchors()
        val (parsed, req, result) = Service.runCheck(pemText, anchors, store.policy(), verifyAt, host, eku, leaf)

        val pemByFp = parsed.certificates.associate {
            val info = CertModel.describe(it)
            info.fingerprint to Service.toPem(it)
        }
        val reqMap = linkedMapOf(
            "verifyAt" to verifyAt.toString(), "host" to host, "eku" to eku,
            "leafFingerprint" to leaf, "certCount" to parsed.certificates.size
        )
        val resultMap = Service.resultDto(result, includePem = false, inputPemByFp = pemByFp)
        val checkId = store.saveCheck(reqMap, resultMap)

        val out: Map<String, Any?> = if (proof) {
            @Suppress("UNCHECKED_CAST")
            (Service.proofDto(result, req, store.session.revision, anchors) as Map<String, Any?>) + mapOf("checkId" to checkId)
        } else {
            linkedMapOf<String, Any?>("checkId" to checkId, "sessionRevision" to store.session.revision) +
                Service.resultDto(result, includePem = true, pemByFp)
        }
        respond(ex, 200, out)
    }

    private fun queryParam(ex: HttpExchange, name: String): String? =
        ex.requestURI.rawQuery?.split("&")?.mapNotNull {
            val kv = it.split("=", limit = 2)
            if (kv.first() == name) java.net.URLDecoder.decode(kv.getOrNull(1) ?: "", "UTF-8") else null
        }?.firstOrNull()

    private class Handled : RuntimeException()

    private fun body(ex: HttpExchange): Map<String, Any?> {
        val raw = ex.requestBody.bufferedReader(StandardCharsets.UTF_8).readText()
        if (raw.isBlank()) return emptyMap()
        return try {
            Json.parseObject(raw)
        } catch (e: Exception) {
            respond(ex, 400, mapOf("error" to "请求 JSON 解析失败: ${e.message}"))
            throw Handled()
        }
    }

    private fun respond(ex: HttpExchange, code: Int, payload: Any?) {
        val bytes = Json.stringify(payload).toByteArray(StandardCharsets.UTF_8)
        ex.responseHeaders.add("Content-Type", "application/json; charset=utf-8")
        ex.sendResponseHeaders(code, bytes.size.toLong())
        ex.responseBody.use { it.write(bytes) }
    }

    private fun guarded(handler: (HttpExchange) -> Unit): com.sun.net.httpserver.HttpHandler =
        com.sun.net.httpserver.HttpHandler { ex ->
            try {
                handler(ex)
            } catch (_: Handled) {
                // response already sent
            } catch (e: Exception) {
                runCatching { respond(ex, 400, mapOf("error" to (e.message ?: e.javaClass.simpleName))) }
            }
        }
}
