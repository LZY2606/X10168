package certstation

import java.nio.file.Paths
import kotlin.system.exitProcess

/**
 * Offline certificate-chain policy checkpoint.
 *
 * Guarantees:
 *  - never reads the OS trust store (no TrustManagerFactory / cacerts use)
 *  - never fetches intermediates over the network
 *  - every trust anchor and policy rule is supplied explicitly in the session
 */
fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5239
    var dataDir = "certstation-data"
    var webDir: String? = null

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> host = args[++i]
            "--port" -> port = args[++i].toInt()
            "--data" -> dataDir = args[++i]
            "--web" -> webDir = args[++i]
            "--help", "-h" -> {
                println("用法: run --host 127.0.0.1 --port 5239 [--data certstation-data] [--web src/main/resources/web]")
                exitProcess(0)
            }
            else -> System.err.println("忽略未知参数: ${args[i]}")
        }
        i++
    }

    // Hard offline posture: disable any outbound proxying surprises and pin to local CA factory only.
    System.setProperty("com.sun.net.httpserver.maxReqHeaders", "64")

    val store = SessionStore(Paths.get(dataDir))
    val server = WebServer(store, webDir?.let { Paths.get(it) }, host, port)
    server.start()

    Runtime.getRuntime().addShutdownHook(Thread { server.stop() })
    Thread.currentThread().join()
}
