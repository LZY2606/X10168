package certstation

/**
 * Tiny JSON reader/writer — enough for the station's API and persistence, no third-party deps.
 */
object Json {
    fun stringify(value: Any?): String = StringBuilder().also { write(it, value) }.toString()

    @Suppress("UNCHECKED_CAST")
    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(v)
            is Number -> sb.append(v.toString())
            is String -> writeString(sb, v)
            is Map<*, *> -> {
                sb.append('{')
                v.entries.forEachIndexed { i, e ->
                    if (i > 0) sb.append(',')
                    writeString(sb, e.key.toString())
                    sb.append(':')
                    write(sb, e.value)
                }
                sb.append('}')
            }
            is Iterable<*> -> {
                sb.append('[')
                v.forEachIndexed { i, e -> if (i > 0) sb.append(','); write(sb, e) }
                sb.append(']')
            }
            is Array<*> -> write(sb, v.toList())
            else -> writeString(sb, v.toString())
        }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (ch in s) when (ch) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            '\b' -> sb.append("\\b")
            '\u000C' -> sb.append("\\f")
            else -> if (ch.code < 0x20) sb.append("\\u%04x".format(ch.code)) else sb.append(ch)
        }
        sb.append('"')
    }

    // --- parser ---
    fun parse(input: String): Any? {
        val p = Parser(input)
        val v = p.readValue()
        p.ws()
        require(p.atEnd()) { "trailing JSON content" }
        return v
    }

    @Suppress("UNCHECKED_CAST")
    fun parseObject(input: String): Map<String, Any?> = parse(input) as Map<String, Any?>

    private class Parser(val s: String, var i: Int = 0) {
        fun atEnd(): Boolean = i >= s.length

        fun ws() { while (i < s.length && s[i].isWhitespace()) i++ }

        fun readValue(): Any? {
            ws()
            if (i >= s.length) error("unexpected end")
            return when (s[i]) {
                '{' -> readObject()
                '[' -> readArray()
                '"' -> readString()
                't', 'f' -> readBool()
                'n' -> readNull()
                else -> readNumber()
            }
        }

        private fun readObject(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++ // {
            ws()
            if (s[i] == '}') { i++; return m }
            while (true) {
                ws()
                val key = readString()
                ws(); require(s[i] == ':') { "expected ':'" }; i++
                m[key] = readValue()
                ws()
                when (s[i]) {
                    ',' -> { i++; continue }
                    '}' -> { i++; break }
                    else -> error("expected , or }")
                }
            }
            return m
        }

        private fun readArray(): List<Any?> {
            val l = ArrayList<Any?>()
            i++ // [
            ws()
            if (s[i] == ']') { i++; return l }
            while (true) {
                l += readValue()
                ws()
                when (s[i]) {
                    ',' -> { i++; continue }
                    ']' -> { i++; break }
                    else -> error("expected , or ]")
                }
            }
            return l
        }

        private fun readString(): String {
            require(s[i] == '"'); i++
            val sb = StringBuilder()
            while (true) {
                val c = s[i++]
                if (c == '"') break
                if (c != '\\') sb.append(c)
                else when (val e = s[i++]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    '/' -> sb.append('/')
                    'n' -> sb.append('\n')
                    't' -> sb.append('\t')
                    'r' -> sb.append('\r')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'u' -> {
                        val hex = s.substring(i, i + 4); i += 4
                        sb.append(hex.toInt(16).toChar())
                    }
                    else -> error("bad escape $e")
                }
            }
            return sb.toString()
        }

        private fun readBool(): Boolean =
            if (s.startsWith("true", i)) { i += 4; true } else { require(s.startsWith("false", i)); i += 5; false }

        private fun readNull(): Any? {
            require(s.startsWith("null", i)); i += 4; return null
        }

        private fun readNumber(): Any {
            val start = i
            if (s[i] == '-') i++
            while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
            val t = s.substring(start, i)
            return if (t.any { it in ".eE" }) t.toDouble() else t.toLong()
        }
    }
}

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.str(key: String, default: String = ""): String = (this[key] as? String) ?: default

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.map(key: String): Map<String, Any?> = (this[key] as? Map<String, Any?>) ?: emptyMap()

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.list(key: String): List<Any?> = (this[key] as? List<Any?>) ?: emptyList()
