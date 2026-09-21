package checkpoint.web

import java.math.BigDecimal

sealed class JsonValue {
    data class Obj(val value: LinkedHashMap<String, JsonValue> = LinkedHashMap()) : JsonValue()
    data class Arr(val value: MutableList<JsonValue> = mutableListOf()) : JsonValue()
    data class Str(val value: String) : JsonValue()
    data class Num(val value: BigDecimal) : JsonValue()
    data class Bool(val value: Boolean) : JsonValue()
    object Null : JsonValue()
}

class JsonParseException(message: String, val position: Int) : RuntimeException("$message at $position")

object JsonParser {
    fun parse(input: String): JsonValue {
        val p = Parser(input)
        p.skipWs()
        val v = p.readValue()
        p.skipWs()
        p.expectEnd()
        return v
    }

    private class Parser(private val s: String) {
        private var i = 0

        fun skipWs() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun expectEnd() {
            if (i != s.length) throw JsonParseException("Unexpected trailing content", i)
        }

        fun readValue(): JsonValue {
            skipWs()
            if (i >= s.length) throw JsonParseException("Unexpected end", i)
            return when (s[i]) {
                '{' -> readObject()
                '[' -> readArray()
                '"' -> JsonValue.Str(readString())
                't', 'f' -> readBoolean()
                'n' -> readNull()
                else -> readNumber()
            }
        }

        private fun readObject(): JsonValue.Obj {
            val obj = JsonValue.Obj()
            i++
            skipWs()
            if (i < s.length && s[i] == '}') { i++; return obj }
            while (true) {
                skipWs()
                if (i >= s.length || s[i] != '"') throw JsonParseException("Expected string key", i)
                val key = readString()
                skipWs()
                if (i >= s.length || s[i] != ':') throw JsonParseException("Expected ':'", i)
                i++
                obj.value[key] = readValue()
                skipWs()
                when {
                    i >= s.length -> throw JsonParseException("Unterminated object", i)
                    s[i] == ',' -> { i++; continue }
                    s[i] == '}' -> { i++; return obj }
                    else -> throw JsonParseException("Expected ',' or '}'", i)
                }
            }
        }

        private fun readArray(): JsonValue.Arr {
            val arr = JsonValue.Arr()
            i++
            skipWs()
            if (i < s.length && s[i] == ']') { i++; return arr }
            while (true) {
                arr.value.add(readValue())
                skipWs()
                when {
                    i >= s.length -> throw JsonParseException("Unterminated array", i)
                    s[i] == ',' -> { i++; continue }
                    s[i] == ']' -> { i++; return arr }
                    else -> throw JsonParseException("Expected ',' or ']'", i)
                }
            }
        }

        fun readString(): String {
            if (s[i] != '"') throw JsonParseException("Expected string", i)
            i++
            val sb = StringBuilder()
            while (i < s.length) {
                val c = s[i]
                when {
                    c == '"' -> { i++; return sb.toString() }
                    c == '\\' -> {
                        i++
                        if (i >= s.length) throw JsonParseException("Bad escape", i)
                        when (val e = s[i]) {
                            '"', '\\', '/' -> sb.append(e)
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (i + 4 >= s.length) throw JsonParseException("Bad unicode escape", i)
                                sb.append(s.substring(i + 1, i + 5).toInt(16).toChar())
                                i += 4
                            }
                            else -> throw JsonParseException("Invalid escape '$e'", i)
                        }
                        i++
                    }
                    else -> { sb.append(c); i++ }
                }
            }
            throw JsonParseException("Unterminated string", i)
        }

        private fun readBoolean(): JsonValue {
            return when {
                s.startsWith("true", i) -> { i += 4; JsonValue.Bool(true) }
                s.startsWith("false", i) -> { i += 5; JsonValue.Bool(false) }
                else -> throw JsonParseException("Invalid literal", i)
            }
        }

        private fun readNull(): JsonValue {
            if (!s.startsWith("null", i)) throw JsonParseException("Invalid literal", i)
            i += 4
            return JsonValue.Null
        }

        private fun readNumber(): JsonValue {
            val start = i
            if (s[i] == '-') i++
            while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
            val raw = s.substring(start, i)
            if (raw.isEmpty() || raw == "-") throw JsonParseException("Invalid number", start)
            return JsonValue.Num(BigDecimal(raw))
        }
    }
}

object JsonWriter {
    fun render(value: Any?): String {
        val sb = StringBuilder()
        write(sb, value)
        return sb.toString()
    }

    private fun write(sb: StringBuilder, value: Any?) {
        when (value) {
            null -> sb.append("null")
            is Boolean -> sb.append(value)
            is Number -> sb.append(value.toString())
            is String -> writeString(sb, value)
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, v) in value) {
                    if (!first) sb.append(',')
                    first = false
                    writeString(sb, k.toString())
                    sb.append(':')
                    write(sb, v)
                }
                sb.append('}')
            }
            is Iterable<*> -> {
                sb.append('[')
                var first = true
                for (v in value) {
                    if (!first) sb.append(',')
                    first = false
                    write(sb, v)
                }
                sb.append(']')
            }
            is Enum<*> -> writeString(sb, value.name)
            else -> writeString(sb, value.toString())
        }
    }

    fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (c.code < 0x20) {
                    sb.append("\\u%04x".format(c.code))
                } else {
                    sb.append(c)
                }
            }
        }
        sb.append('"')
    }
}
