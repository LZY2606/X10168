package checkpoint

import checkpoint.chain.AnchorInput
import checkpoint.chain.CheckInput
import checkpoint.chain.CheckService
import checkpoint.model.PolicyVersion
import checkpoint.model.PolicySet
import java.time.Instant

object TestSupport {
    fun policy(
        rsa: Int = 2048,
        ec: Int = 224,
        sha1RetiredAt: String? = "2017-01-01T00:00:00Z",
        version: String = "test-v1",
        rsaRetiredAt: String? = null
    ): PolicySet {
        val retired = buildMap {
            if (sha1RetiredAt != null) put("SHA1", Instant.parse(sha1RetiredAt))
            if (rsaRetiredAt != null) put("RSA", Instant.parse(rsaRetiredAt))
        }
        return PolicySet(
            listOf(
                PolicyVersion(
                    version = version,
                    effectiveAt = Instant.parse("1970-01-01T00:00:00Z"),
                    minKeyBitsRsa = rsa,
                    minKeyBitsEc = ec,
                    retiredAlgorithms = retired
                )
            )
        )
    }

    fun multiVersionPolicy(): PolicySet = PolicySet(
        listOf(
            PolicyVersion(
                version = "v-2015",
                effectiveAt = Instant.parse("2015-01-01T00:00:00Z"),
                minKeyBitsRsa = 1024,
                retiredAlgorithms = emptyMap()
            ),
            PolicyVersion(
                version = "v-2020",
                effectiveAt = Instant.parse("2020-01-01T00:00:00Z"),
                minKeyBitsRsa = 2048,
                retiredAlgorithms = mapOf("SHA1" to Instant.parse("2020-01-01T00:00:00Z"))
            )
        )
    )

    fun check(
        bundle: String,
        anchors: List<Pair<String, GeneratedCert>>,
        host: String? = "example.com",
        purpose: String? = "serverAuth",
        at: String = "2024-06-01T12:00:00Z",
        policy: PolicySet = policy()
    ) = CheckService().check(
        CheckInput(
            bundlePem = bundle,
            anchors = anchors.map { (label, c) -> AnchorInput(label, c.pem()) },
            hostname = host,
            purpose = purpose,
            verifyAtText = at,
            policy = policy
        )
    )
}
