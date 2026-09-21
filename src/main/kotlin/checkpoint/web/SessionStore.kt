package checkpoint.web

import checkpoint.chain.AnchorInput
import checkpoint.chain.CheckReport
import checkpoint.model.PolicySet
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class SessionSnapshot(
    val version: Int,
    val createdAt: Instant,
    val anchors: List<AnchorInput>,
    val policy: PolicySet
)

data class StoredSession(
    val id: String,
    val createdAt: Instant,
    @Volatile var currentVersion: Int,
    val snapshots: MutableList<SessionSnapshot> = mutableListOf(),
    val reports: MutableMap<Int, CheckReport> = ConcurrentHashMap()
)

class SessionStore {
    private val sessions = ConcurrentHashMap<String, StoredSession>()

    fun create(anchors: List<AnchorInput>, policy: PolicySet): StoredSession {
        val id = UUID.randomUUID().toString()
        val session = StoredSession(id, Instant.now(), 1)
        session.snapshots += SessionSnapshot(1, Instant.now(), anchors, policy)
        sessions[id] = session
        return session
    }

    fun get(id: String): StoredSession? = sessions[id]

    fun getOrCreate(id: String?, anchors: List<AnchorInput>, policy: PolicySet): StoredSession {
        if (id != null) {
            val existing = sessions[id]
            if (existing != null) {
                synchronized(existing) {
                    val last = existing.snapshots.last()
                    if (last.anchors != anchors || !policiesEqual(last.policy, policy)) {
                        val next = existing.currentVersion + 1
                        existing.currentVersion = next
                        existing.snapshots += SessionSnapshot(next, Instant.now(), anchors, policy)
                    }
                }
                return existing
            }
        }
        return create(anchors, policy)
    }

    private fun policiesEqual(a: PolicySet, b: PolicySet): Boolean = a == b

    fun storeReport(session: StoredSession, report: CheckReport) {
        session.reports[session.currentVersion] = report
    }

    fun snapshot(session: StoredSession, version: Int?): SessionSnapshot? {
        val v = version ?: session.currentVersion
        return session.snapshots.firstOrNull { it.version == v }
    }
}
