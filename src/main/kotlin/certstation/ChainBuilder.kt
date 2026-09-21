package certstation

import java.security.cert.X509Certificate

data class TrustAnchor(
    val id: String,
    val priority: Int,
    val info: CertInfo
)

/**
 * One concrete certificate path, ordered leaf -> anchor.
 * [complete] is false when DFS exhausted without reaching a trust anchor.
 */
data class ChainCandidate(
    val certificates: List<CertInfo>, // leaf first, terminal last
    val anchor: TrustAnchor?,
    val complete: Boolean,
    val chainFingerprint: String
)

object ChainBuilder {
    private const val MAX_DEPTH = 12

    /**
     * @param inputCerts unordered certificates pasted in the session
     * @param anchors explicit trust anchors (never taken from OS trust store)
     * @param leafFingerprint target leaf; null means every non-CA input cert is a leaf
     */
    fun enumerate(
        inputCerts: List<CertInfo>,
        anchors: List<TrustAnchor>,
        leafFingerprint: String? = null
    ): List<ChainCandidate> {
        // Parents are anything that could issue: provided certs plus anchors.
        // Anchors win only as terminal nodes, never as intermediates for another step.
        val all: List<CertInfo> = inputCerts
        val anchorByFp = anchors.associateBy { it.info.fingerprint }
        val bySubject: Map<String, List<CertInfo>> =
            (all + anchors.map { it.info }).groupBy { it.subjectCanonical }
                .mapValues { (_, v) -> v.sortedBy { it.fingerprint } }

        val explicitLeaves = all.filter { it.fingerprint == leafFingerprint }
        val endEntityLeaves = all.filter { !it.isCa }
        // When no end-entity cert is present, treat certificates that no other provided
        // certificate chains from as candidate leaves too (e.g. user pasted a CA-only bundle).
        val referencedAsIssuer = all.mapNotNull { c ->
            all.firstOrNull { other ->
                other.fingerprint != c.fingerprint &&
                    other.issuerCanonical == c.subjectCanonical &&
                    other.subjectCanonical != c.subjectCanonical
            }
        }.map { it.fingerprint }.toSet()
        val danglingLeaves = if (endEntityLeaves.isEmpty())
            all.filter { it.fingerprint !in referencedAsIssuer }
        else emptyList()
        val leaves: List<CertInfo> = when {
            leafFingerprint != null -> explicitLeaves
            else -> (endEntityLeaves + danglingLeaves).distinctBy { it.fingerprint }
        }
        val orderedLeaves = leaves.sortedBy { it.fingerprint }

        val results = ArrayList<ChainCandidate>()
        for (leaf in orderedLeaves) {
            dfs(leaf, arrayListOf(leaf), linkedSetOf(leaf.fingerprint), bySubject, anchorByFp, results)
        }
        // de-duplicate identical chains and sort for stable presentation
        val unique = results.distinctBy { c -> c.certificates.joinToString(",") { it.fingerprint } + "|" + (c.anchor?.id ?: "") }
        return unique.sortedWith(
            compareBy({ it.certificates.size }, { it.anchor?.priority ?: Int.MAX_VALUE }, { it.chainFingerprint })
        )
    }

    private fun dfs(
        current: CertInfo,
        path: ArrayList<CertInfo>,
        onPath: LinkedHashSet<String>,
        bySubject: Map<String, List<CertInfo>>,
        anchorByFp: Map<String, TrustAnchor>,
        results: ArrayList<ChainCandidate>
    ) {
        // 1) Direct trust: current certificate is itself an anchor.
        anchorByFp[current.fingerprint]?.let {
            emit(path, it, results)
            return
        }

        // 2) Find candidate issuers by subject/issuer DN equality (stable fingerprint order).
        val parents = bySubject[current.issuerCanonical].orEmpty()
            .filter { it.fingerprint !in onPath }
            .filter { parent -> keyIdsConsistent(current, parent) }

        if (path.size >= MAX_DEPTH) {
            emit(path, null, results)
            return
        }
        if (parents.isEmpty()) {
            emit(path, null, results)
            return
        }

        var extendable = false
        for (parent in parents) {
            // Self-signed parent that is not an anchor cannot validate; record dead end once.
            if (parent.isSelfSigned && parent.fingerprint !in anchorByFp) {
                // keep walking nowhere for it; emit incomplete after loop if nothing else
                continue
            }
            extendable = true
            path += parent
            onPath += parent.fingerprint
            dfs(parent, path, onPath, bySubject, anchorByFp, results)
            onPath -= parent.fingerprint
            path.removeAt(path.size - 1)
        }
        if (!extendable) emit(path, null, results)
    }

    private fun emit(path: List<CertInfo>, anchor: TrustAnchor?, results: ArrayList<ChainCandidate>) {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        for (c in path) md.update(c.fingerprint.removePrefix("sha256:").chunked(2).map { it.toInt(16).toByte() }.toByteArray())
        val fp = "sha256:" + CertModel.hex(md.digest())
        results += ChainCandidate(path.toList(), anchor, anchor != null, fp)
    }

    private fun keyIdsConsistent(child: CertInfo, parent: CertInfo): Boolean {
        val aki = child.authorityKeyId ?: return true
        val ski = parent.subjectKeyId ?: return true
        return aki == ski
    }
}
