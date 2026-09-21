package checkpoint

import checkpoint.web.CheckpointHttpServer

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5239
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> { host = args[i + 1]; i += 2 }
            "--port" -> { port = args[i + 1].toInt(); i += 2 }
            else -> { System.err.println("未知参数: ${args[i]}"); kotlin.system.exitProcess(2) }
        }
    }
    CheckpointHttpServer(host, port).start()
}
