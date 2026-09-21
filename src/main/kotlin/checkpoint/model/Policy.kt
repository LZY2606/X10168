package checkpoint.model

import java.time.Instant

/**
 * 检查策略（版本化）。每个版本从 effectiveAt 起生效；验证时选择 notBefore <= 验证时刻
 * 的最新版本。算法在 retiredAt 当日（含）起淘汰；最小密钥长度按公钥算法区分。
 */
data class PolicyVersion(
    val version: String,
    val effectiveAt: Instant,
    val minKeyBitsRsa: Int = 2048,
    val minKeyBitsEc: Int = 224,
    /** 算法家族 -> 退役时刻（该时刻含起视为退役），如 "SHA1"、"RSA"、"ECDSA" */
    val retiredAlgorithms: Map<String, Instant> = emptyMap()
) {
    fun isRetired(algorithmFamily: String, at: Instant): Instant? =
        retiredAlgorithms[algorithmFamily.uppercase()]?.takeIf { !at.isBefore(it) }
}

data class PolicySet(val versions: List<PolicyVersion>) {
    init {
        require(versions.isNotEmpty()) { "策略至少需要一个版本" }
    }

    fun at(instant: Instant): PolicyVersion =
        versions.filter { !instant.isBefore(it.effectiveAt) }
            .maxByOrNull { it.effectiveAt }
            ?: versions.first()
}
