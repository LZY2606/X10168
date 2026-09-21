package checkpoint.chain

import checkpoint.model.CertInfo

/**
 * 从输入证书到显式 trust anchor 的原始候选链（不做策略校验）。
 * 证书按 subject 索引；同 subject 多证书、交叉签发生成多条路径。
 */
data class RawChain(
    /** 叶子 -> ... -> 锚点 */
    val certs: List<CertInfo>,
    val anchor: CertInfo?,
    /** anchor_unreachable / cycle / max_depth / none */
    val terminal: String,
    val anchorPriority: Int?
)

class ChainBuilder(
    private val anchors: List<CertInfo>,
    intermediateCerts: List<CertInfo>,
    private val maxDepth: Int = 12
) {
    // subject DN（规范化大写）-> 证书列表
    private val bySubject: Map<String, List<CertInfo>>
    private val anchorSet: Set<String> = anchors.map { it.fingerprintSha256 }.toSet()
    private val anchorOrder: Map<String, Int> =
        anchors.mapIndexed { idx, c -> c.fingerprintSha256 to idx + 1 }.toMap()

    init {
        val all = anchors + intermediateCerts
        bySubject = all.groupBy { normalizeDn(it.subjectDn) }
    }

    /** 叶子候选：没有任何非锚证书把它当作签发者（DAG 中无入边）。 */
    fun leafCandidates(): List<CertInfo> {
        val nonAnchor = bySubject.values.flatten().filter { it.fingerprintSha256 !in anchorSet }
        val signedBy = mutableSetOf<String>()
        for (c in nonAnchor) {
            for (issuer in issuersOf(c)) {
                if (issuer.fingerprintSha256 !in anchorSet) {
                    signedBy += issuer.fingerprintSha256
                }
            }
        }
        val leaves = nonAnchor.filter { it.fingerprintSha256 !in signedBy }
        return leaves.ifEmpty { nonAnchor }
    }

    fun enumerate(): List<RawChain> {
        val results = mutableListOf<RawChain>()
        for (leaf in leafCandidates()) {
            dfs(leaf, listOf(leaf), setOf(leaf.fingerprintSha256), results)
        }
        // 按链指纹去重（同 leaf/路径）
        return results.distinctBy { rawFingerprint(it) }
    }

    private fun dfs(
        current: CertInfo,
        path: List<CertInfo>,
        visited: Set<String>,
        results: MutableList<RawChain>
    ) {
        // 自签：只有它是显式 anchor 才能终止
        if (current.isSelfSigned) {
            if (current.fingerprintSha256 in anchorSet) {
                results += RawChain(path, current, "none", anchorOrder[current.fingerprintSha256])
            } else {
                results += RawChain(path, null, "anchor_unreachable", null)
            }
            return
        }

        val issuers = issuersOf(current)
        val anchored = issuers.filter { it.fingerprintSha256 in anchorSet }
        val nonAnchored = issuers.filter { it.fingerprintSha256 !in anchorSet }

        for (anchor in anchored) {
            results += RawChain(path + anchor, anchor, "none", anchorOrder[anchor.fingerprintSha256])
        }

        if (issuers.isEmpty()) {
            results += RawChain(path, null, "anchor_unreachable", null)
            return
        }

        for (next in nonAnchored) {
            if (next.fingerprintSha256 in visited) {
                results += RawChain(path + next, null, "cycle", null)
                continue
            }
            if (path.size >= maxDepth) {
                results += RawChain(path + next, null, "max_depth", null)
                continue
            }
            dfs(next, path + next, visited + next.fingerprintSha256, results)
        }
    }

    private fun issuersOf(cert: CertInfo): List<CertInfo> {
        val candidates = bySubject[normalizeDn(cert.issuerDn)] ?: return emptyList()
        // 仅按 subject DN 枚举所有结构候选；AKI/SKI 与真实密钥归属交给签名校验定位，
        // 这样同名中间、交叉签发导致的错误路径也会作为失败链被完整解释。
        return candidates.filter { it.fingerprintSha256 != cert.fingerprintSha256 }
    }

    private fun normalizeDn(dn: String): String = dn.replace("\\s+".toRegex(), "").uppercase()

    private fun rawFingerprint(chain: RawChain): String =
        chain.certs.joinToString("|") { it.fingerprintSha256 }
}
