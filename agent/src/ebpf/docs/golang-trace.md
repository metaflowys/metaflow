# Golang Trace

## uretprobe

[Go 不支持 uretprobe](https://github.com/golang/go/issues/22008),
使用 uretprobe 会导致被 attach 的进程 crash,
使用普通的 uprobe 并 attach 到函数返回指令地址可以解决这个问题.

### 函数返回地址获取

函数返回地址的计算依赖:

1. 函数起始地址
2. 函数结束地址(或函数长度)
3. x86 字节流到指令的翻译

重点在于字节流到指令的翻译,在文件中读出的函数本质上是一个字节流,
需要将字节流翻译成对应的指令,才能确定函数返回指令,
如果不这样做可能导致其他指令中的一部分被误识别成返回指令.
因此当前实现仅支持 x86 架构.

## eBPF 中获取当前 Go 线程的协程号

### Hook 点

`runtime.casgstatus`

## Go TLS HTTP1

HTTP1 存在多个 hook 点, 一部分存在版本变化导致 hook 点失效的问题,又或者是不能拿到需要的原始报文.
结合已有的 HTTP1 解析实现,选择相对稳定的 TLS 加解密作为 hook 点,同时未来也可以支持 TLS 加密的其他协议(目前已经屏蔽,仅处理HTTP1)

### Go TLS HTTP1 Hook

* `crypto/tls.(*Conn).Write`
* `crypto/tls.(*Conn).Read`

这两个符号名在目前支持的 Go (1.13-1.18) 版本都有效.

## Go HTTP2

参考[uprobetracer](https://01.org/linuxgraphics/gfx-docs/drm/trace/uprobetracer.html)测试

没有导出符号,符号表里找不到,需要读调试信息

* `net/http.(*http2serverConn).writeHeaders`(new) <- `golang.org/x/net/http2.(*serverConn).writeHeaders`(old)
* `net/http.(*http2serverConn).processHeaders`(new) <- `golang.org/x/net/http2.(*serverConn).processHeaders`(old)
* `net/http.(*http2clientConnReadLoop).handleResponse`(new) <- `golang.org/x/net/http2.(*clientConnReadLoop).handleResponse`(old)
* `net/http.(*http2ClientConn).writeHeaders`(new) <- `golang.org/x/net/http2.(*ClientConn).writeHeaders`(old)
* `net/http.(*http2ClientConn).writeHeader`(new) <- `golang.org/x/net/http2.(*ClientConn).writeHeader`(old)
* `google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader`
* `google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders`
* `google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders`

### 从 net.Conn 到 net.TCPConn 或 crypto/tls.Conn

http2 和 grpc 都存在使用 tls (tls->tcp) 和不使用 tls (直接使用tcp)的情况,
在 golang 实现里, 他们的差异是 interface 对应的 struct 类型不同, 因此需要判断 interface 对应的 struct.

[深入研究 Go interface 底层实现](https://halfrost.com/go_interface/)介绍了 go interface 的内存布局,以及 go interface 到 struct 映射的方法.

```go
type iface struct {
	tab  *itab
	data unsafe.Pointer
}
```

简而言之,当确定了 tab 的值就可以确定某个 interface 对应的类型.
在 eBPF 中,可以从 uprobe 获取到 interface 的地址,再根据 iface 的结构获取到 tab.
由于 tab 在编译时确定, 所以所需类型(net.TCPConn,crypto/tls.Conn)对应的 tab 值要由上层应用下发到 eBPF.

上层应用可以读可执行文件的符号表获取 tab 值.

### 从 uprobe 获取 socket 信息

从进行操作的对象(对于go来说是函数的第一个结构体参数)中, 获取 socket 信息.
由于 interface 和继承 (对于go来说组合一个匿名结构体)的存在,这个过程会很复杂(可能会根据不同版本进行调整),
但本质上是从函数参数开始调整指针最终获取到需要的内存的过程.

0 到 4 是一组 http2 web 请求响应.
5 到 8 是一组 grpc 的请求响应.

需要注意,这里发送和接收的 tcp seq 对应不上,通过 tcpdump 抓包确认,
实际上在进入 read 类的函数的时候,已经完成了从 socket 读数据的步骤,
因此此时读到的序列号都是靠后的,或者说,向后偏移了原始 tcp 报文的长度.

```txt
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
0. http2ClientConn writeHeader fd=[10] tcp_seq=[878799606]
1. http2ClientConn writeHeaders fd=[10] tcp_seq=[878799606]
2. http2serverConn processHeaders fd=[11] tcp_seq=[878799643]
3. http2serverConn writeHeaders fd=[11] tcp_seq=[2149142185]
4. http2clientConnReadLoop handleResponse fd=[10] tcp_seq=[2149142243]
5. grpc client write fd=[8] tcp_seq=[1539219396]
6. grpc server read fd=[9] tcp_seq=[1539219473]
7. grpc server write fd=[9] tcp_seq=[3867751365]
7. grpc server write fd=[9] tcp_seq=[3867751365]
8. grpc client read fd=[8] tcp_seq=[3867751502]
8. grpc client read fd=[8] tcp_seq=[3867751502]
```
