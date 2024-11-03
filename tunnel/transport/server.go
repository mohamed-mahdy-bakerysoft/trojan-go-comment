package transport

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

// Server is a server of transport layer
type Server struct {
	tcpListener net.Listener
	cmd         *exec.Cmd
	connChan    chan tunnel.Conn // 传递连接给上层 trojan 协议的通道
	wsChan      chan tunnel.Conn // 传递连接给上层 websocket 协议的通道
	httpLock    sync.RWMutex     // 读写锁，用来锁定 nextHTTP 操作
	nextHTTP    bool             // 判断是否启用明文 HTTP 模式，默认为false
	ctx         context.Context
	cancel      context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
	return s.tcpListener.Close()
}

func (s *Server) acceptLoop() {
	for {
		// 循环接收连接
		tcpConn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done(): // cancel() 取消协程
			default:
				log.Error(common.NewError("transport accept error").Base(err))
				time.Sleep(time.Millisecond * 100)
			}
			return // 在接受连接出错后终止循环，意味着服务器不再接受新的连接
		}

		go func(tcpConn net.Conn) {
			log.Info("tcp connection from", tcpConn.RemoteAddr())
			s.httpLock.RLock() // 获取读锁，确保在检查 s.nextHTTP 时其他协程不会修改共享状态
			if s.nextHTTP {    // plaintext mode enabled
				s.httpLock.RUnlock()
				// we use real http header parser to mimic a real http server
				// 我们使用真实的http标头解析器来模仿真实的http服务器
				rewindConn := common.NewRewindConn(tcpConn) // 重放作用应该是为了读取并检测，不会真正读取缓冲区中数据
				rewindConn.SetBufferSize(512)
				defer rewindConn.StopBuffering()

				r := bufio.NewReader(rewindConn)
				// 尝试解析 HTTP 请求。如果成功，httpReq 将包含请求信息；如果失败，err 将包含错误信息
				httpReq, err := http.ReadRequest(r)
				rewindConn.Rewind() // 重置读取索引
				rewindConn.StopBuffering()
				if err != nil {
					// this is not a http request, pass it to trojan protocol layer for further inspection
					// 这不是一个http请求，将其传递给木马协议层进行进一步检查
					s.connChan <- &Conn{
						Conn: rewindConn,
					}
				} else {
					// this is a http request, pass it to websocket protocol layer
					// 这是一个http请求，将其传递给websocket协议层
					log.Debug("plaintext http request: ", httpReq)
					s.wsChan <- &Conn{
						Conn: rewindConn,
					}
				}
			} else {
				s.httpLock.RUnlock()
				s.connChan <- &Conn{
					Conn: tcpConn,
				}
			}
		}(tcpConn)
	}
}

// 让上一层协议获取当前协议层的连接，支持向上层提供 TCP 流
func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	// TODO fix import cycle
	if overlay != nil && (overlay.Name() == "WEBSOCKET" || overlay.Name() == "HTTP") {
		s.httpLock.Lock()
		s.nextHTTP = true // 是否启用明文 HTTP 模式
		s.httpLock.Unlock()
		select {
		// 没有连接会阻塞
		case conn := <-s.wsChan:
			return conn, nil
		case <-s.ctx.Done():
			return nil, common.NewError("transport server closed")
		}
	}
	select {
	// 没有连接会阻塞
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("transport server closed")
	}
}

// 不支持向上层提供 UDP 包
func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

// NewServer creates a transport layer server
func NewServer(ctx context.Context, _ tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	listenAddress := tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)

	var cmd *exec.Cmd
	if cfg.TransportPlugin.Enabled { // 是否开启传输层插件
		log.Warn("transport server will use plugin and work in plain text mode")
		switch cfg.TransportPlugin.Type {
		case "shadowsocks": // 只是一个类型符号，代表类似 shadowsocks 插件 如 v2ray-plugin
			trojanHost := "127.0.0.1"                        // trojan-go 默认host
			trojanPort := common.PickPort("tcp", trojanHost) // 随机为 trojan-go 获取端口
			cfg.TransportPlugin.Env = append(
				cfg.TransportPlugin.Env,                                       // 插件环境变量
				"SS_REMOTE_HOST="+cfg.LocalHost,                               // shadowsocks 服务端监听地址，即客户端连接的远程服务端地址
				"SS_REMOTE_PORT="+strconv.FormatInt(int64(cfg.LocalPort), 10), // shadowsocks 服务端监听端口，即客户端连接的远程服务端端口
				"SS_LOCAL_HOST="+trojanHost,                                   // shadowsocks 转发的 trojan-go 监听地址
				"SS_LOCAL_PORT="+strconv.FormatInt(int64(trojanPort), 10),     // shadowsocks 转发的 trojan-go 监听端口
				"SS_PLUGIN_OPTIONS="+cfg.TransportPlugin.Option,               // 插件选项
			)

			cfg.LocalHost = trojanHost
			cfg.LocalPort = trojanPort
			// 注意，trojan-go 监听使用 127.0.0.1:随机端口
			listenAddress = tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)
			log.Debug("new listen address", listenAddress)
			log.Debug("plugin env", cfg.TransportPlugin.Env)

			// 执行对应插件命令
			cmd = exec.Command(cfg.TransportPlugin.Command, cfg.TransportPlugin.Arg...)
			cmd.Env = append(cmd.Env, cfg.TransportPlugin.Env...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stdout
			cmd.Start()
		case "other": // 非SIP003标准的插件
			cmd = exec.Command(cfg.TransportPlugin.Command, cfg.TransportPlugin.Arg...)
			cmd.Env = append(cmd.Env, cfg.TransportPlugin.Env...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stdout
			cmd.Start()
		case "plaintext":
			// do nothing
		default:
			return nil, common.NewError("invalid plugin type: " + cfg.TransportPlugin.Type)
		}
	}
	tcpListener, err := net.Listen("tcp", listenAddress.String())
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		tcpListener: tcpListener,
		cmd:         cmd,
		ctx:         ctx,
		cancel:      cancel,
		connChan:    make(chan tunnel.Conn, 32),
		wsChan:      make(chan tunnel.Conn, 32),
	}
	go server.acceptLoop()
	return server, nil
}
