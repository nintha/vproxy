package vproxy.poc

import kotlinx.coroutines.launch
import vproxy.base.connection.ConnectableConnection
import vproxy.base.connection.ConnectionOpts
import vproxy.base.connection.NetEventLoop
import vproxy.base.connection.ServerSock
import vproxy.base.selector.SelectorEventLoop
import vproxy.base.util.RingBuffer
import vproxy.base.util.Version
import vproxy.base.util.thread.VProxyThread
import vproxy.lib.common.fitCoroutine
import vproxy.lib.common.launch
import vproxy.lib.common.sleep
import vproxy.vfd.IPPort

@Suppress("BlockingMethodInNonBlockingContext")
object CoroutineHttp1POC {
  @JvmStatic
  fun main(args: Array<String>) {
    val loop = SelectorEventLoop.open()
    val netLoop = NetEventLoop(loop)
    loop.loop { VProxyThread.create(it, "coroutine-http1-poc") }
    loop.launch {
      val listenPort = 30080
      launch {
        // start server
        val serverSock = ServerSock.create(IPPort("127.0.0.1", listenPort)).fitCoroutine(netLoop)
        while (true) {
          val conn = serverSock.accept().asHttp1ServerConnection()
          println("accepted socket $conn")
          launch {
            val req = conn.readRequest()
            println("server received request: $req")
            conn.newResponse(200).header("Server", "vproxy/" + Version.VERSION)
              .send("Hello World\r\n")
          }
        }
      }

      println("wait for 1 sec on thread: " + Thread.currentThread())
      sleep(1000)
      println("begin request on thread: " + Thread.currentThread())

      val sock = ConnectableConnection.create(
        IPPort("127.0.0.1", listenPort), ConnectionOpts(),
        RingBuffer.allocate(1024), RingBuffer.allocate(1024)
      ).fitCoroutine(netLoop)
      sock.setTimeout(1000)
      sock.connect()
      val conn = sock.asHttp1ClientConnection()
      conn.get("/").header("Host", "example.com").send()
      val resp = conn.readResponse()
      println("client received response: $resp")
      sock.close()

      sleep(1000)
      loop.close()
    }
  }
}
