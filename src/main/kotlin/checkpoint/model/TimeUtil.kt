package checkpoint.model

import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

object TimeUtil {
    private val DATE = DateTimeFormatter.ISO_LOCAL_DATE

    fun parseInstant(text: String): Instant {
        val t = text.trim()
        return runCatching { Instant.parse(t) }.getOrElse {
            runCatching {
                if (t.length == 10) {
                    LocalDate.parse(t, DATE).atStartOfDay().toInstant(ZoneOffset.UTC)
                } else {
                    LocalDateTime.parse(t.replace(" ", "T")).toInstant(ZoneOffset.UTC)
                }
            }.getOrElse { throw IllegalArgumentException("无法解析时间: '$text' (需要 ISO-8601 UTC，如 2024-06-01T00:00:00Z)") }
        }
    }

    fun format(instant: Instant): String = instant.toString()
    fun formatDate(instant: Instant): String =
        DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC).format(instant)
}
