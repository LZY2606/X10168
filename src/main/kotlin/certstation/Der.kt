package certstation

import java.math.BigInteger

/**
 * Minimal DER decoder sufficient for the X.509 extensions this station inspects
 * beyond what java.security.cert.X509Certificate already exposes.
 */
class DerReader(private val bytes: ByteArray, private var pos: Int = 0, private val end: Int = bytes.size) {

    data class Tlv(val tag: Int, val content: ByteArray, val valueOffset: Int) {
        fun reader(): DerReader = DerReader(content)
    }

    fun remaining(): Int = end - pos

    fun readTag(tag: Int): Tlv {
        val t = readTlv()
        require(t.tag == tag) { "expected tag ${tag.toByte().toInt() and 0x1f} got ${t.tag}" }
        return t
    }

    fun readTlv(): Tlv {
        val start = pos
        val tag = bytes[pos++].toInt() and 0xFF
        var length = bytes[pos++].toInt() and 0xFF
        if (length and 0x80 != 0) {
            val numBytes = length and 0x7F
            require(numBytes in 1..4) { "unsupported DER length" }
            length = 0
            repeat(numBytes) { length = (length shl 8) or (bytes[pos++].toInt() and 0xFF) }
        }
        val valueOffset = pos
        val content = bytes.copyOfRange(valueOffset, valueOffset + length)
        pos += length
        return Tlv(tag, content, valueOffset).also { check(pos <= end) { "DER overrun (offset $start)" } }
    }

    fun readSequence(block: (DerReader) -> Unit) {
        val seq = readTag(0x30)
        seq.reader().run(block)
    }

    fun readOid(): String {
        val tlv = readTag(0x06)
        val v = tlv.content
        if (v.isEmpty()) return ""
        val sb = StringBuilder()
        var first = v[0].toInt() and 0xFF
        sb.append(first / 40).append('.').append(first % 40)
        var i = 1
        while (i < v.size) {
            var n = 0L
            while (i < v.size) {
                val b = v[i++].toInt() and 0xFF
                n = (n shl 7) or (b.toLong() and 0x7F)
                if (b and 0x80 == 0) break
            }
            sb.append('.').append(n)
        }
        return sb.toString()
    }

    fun readBoolean(): Boolean {
        val tlv = readTag(0x01)
        return tlv.content[0].toInt() != 0
    }

    fun readInteger(): Int {
        val tlv = readTag(0x02)
        return BigInteger(tlv.content).toInt()
    }

    fun explicitTagged(tag: Int): Tlv {
        val t = readTlv()
        require(t.tag == 0xA0 or tag) { "expected [${tag}] got ${t.tag}" }
        return t
    }

    companion object {
        fun sequenceOf(tlv: Tlv): List<Tlv> {
            val r = tlv.reader()
            val out = ArrayList<Tlv>()
            while (r.remaining() > 0) out += r.readTlv()
            return out
        }

        /** Absolute offset of each top-level TLV within [bytes]. */
        fun topLevelOffsets(bytes: ByteArray): List<Int> {
            val r = DerReader(bytes)
            val out = ArrayList<Int>()
            while (r.remaining() > 0) {
                val start = r.pos
                out += start
                r.readTlv()
            }
            return out
        }
    }
}
