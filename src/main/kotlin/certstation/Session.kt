package certstation

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

data class Session(
    val id: String,
    var revision: Long = 0,
    val anchors: LinkedHashMap<String, AnchorRecord> = LinkedHashMap(),
    var policyEntries: MutableList<PolicyEntry> = AlgorithmPolicy.DEFAULT_ENTRIES.toMutableList(),
    val history: MutableList<SessionRevision> = ArrayList()
)

data class AnchorRecord(
    val id: String,
    val pem: String,
    val fingerprint: String,
    val subject: String,
    val priority: Int,
    val addedAt: Instant
)

data class SessionRevision(
    val revision: Long,
    val at: Instant,
    val kind: String,
    val summary: Map<String, Any?>
)

data class StoredCheck(
    val checkId: Long,
    val at: Instant,
    val request: Map<String, Any?>,
    val result: Map<String, Any?>
)

class SessionStore(private val dir: Path) {
    private val sessionFile = dir.resolve("session.json")
    private val checksDir = dir.resolve("checks")
    private val seq = AtomicLong(0)
    var session: Session
        private set

    init {
        Files.createDirectories(checksDir)
        session = load()
    }

    @Synchronized
    fun <T> mutate(kind: String, summary: Map<String, Any?> = emptyMap(), block: (Session) -> T): T {
        val result = block(session)
        session.revision += 1
        session.history.add(SessionRevision(session.revision, Instant.now(), kind, summary))
        persist(session)
        return result
    }

    @Synchronized
    fun saveCheck(request: Map<String, Any?>, result: Map<String, Any?>): Long {
        val id = seq.incrementAndGet()
        val record = StoredCheck(id, Instant.now(), request, result)
        Files.writeString(
            checksDir.resolve("check-%05d.json".format(id)),
            Json.stringify(toMap(record))
        )
        return id
    }

    fun policy(): AlgorithmPolicy = AlgorithmPolicy(session.policyEntries)

    private fun persist(current: Session) {
        val tmp = dir.resolve("session.tmp.json")
        Files.writeString(tmp, Json.stringify(toMap(current)))
        Files.move(tmp, sessionFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    }

    private fun load(): Session {
        if (!Files.exists(sessionFile)) return Session(id = "session-1").also { persist(it) }
        val raw = Json.parseObject(Files.readString(sessionFile))
        val s = Session(id = raw.str("id"), revision = (raw["revision"] as? Number)?.toLong() ?: 0)
        @Suppress("UNCHECKED_CAST")
        for (a in raw.list("anchors").mapNotNull { it as? Map<String, Any?> }) {
            val rec = AnchorRecord(
                id = a.str("id"),
                pem = a.str("pem"),
                fingerprint = a.str("fingerprint"),
                subject = a.str("subject"),
                priority = (a["priority"] as? Number)?.toInt() ?: 100,
                addedAt = Instant.parse(a.str("addedAt"))
            )
            s.anchors[rec.id] = rec
        }
        for (e in raw.list("policyEntries").mapNotNull { it as? Map<String, Any?> }) {
            s.policyEntries += PolicyEntry(
                id = e.str("id"),
                effectiveAt = Instant.parse(e.str("effectiveAt")),
                kind = e.str("kind"),
                target = e.str("target"),
                minSize = (e["minSize"] as? Number)?.toInt() ?: 0,
                reason = e.str("reason")
            )
        }
        for (h in raw.list("history").mapNotNull { it as? Map<String, Any?> }) {
            s.history += SessionRevision(
                revision = (h["revision"] as? Number)?.toLong() ?: 0,
                at = Instant.parse(h.str("at")),
                kind = h.str("kind"),
                summary = h.map("summary")
            )
        }
        seq.set(s.history.size.toLong())
        return s
    }

    companion object {
        private val B64 = Base64.getEncoder()

        fun toMap(s: Session): Map<String, Any?> = linkedMapOf(
            "id" to s.id,
            "revision" to s.revision,
            "anchors" to s.anchors.values.map {
                linkedMapOf(
                    "id" to it.id, "pem" to it.pem, "fingerprint" to it.fingerprint,
                    "subject" to it.subject, "priority" to it.priority, "addedAt" to it.addedAt.toString()
                )
            },
            "policyEntries" to s.policyEntries.map {
                linkedMapOf(
                    "id" to it.id, "effectiveAt" to it.effectiveAt.toString(),
                    "kind" to it.kind, "target" to it.target,
                    "minSize" to it.minSize, "reason" to it.reason
                )
            },
            "history" to s.history.map {
                linkedMapOf(
                    "revision" to it.revision, "at" to it.at.toString(),
                    "kind" to it.kind, "summary" to it.summary
                )
            }
        )

        fun toMap(c: StoredCheck): Map<String, Any?> = linkedMapOf(
            "checkId" to c.checkId, "at" to c.at.toString(),
            "request" to c.request, "result" to c.result
        )
    }
}
