package trojan

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/p4gefau1t/trojan-go/api"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/redirector"
	"github.com/p4gefau1t/trojan-go/statistic"
	"github.com/p4gefau1t/trojan-go/statistic/memory"
	"github.com/p4gefau1t/trojan-go/statistic/mysql"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/mux"
)

// InboundConn is a trojan inbound connection
type InboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64 // 发送的数据包字节累计
	recv uint64 // 接收的数据包字节累计

	net.Conn                         // 下一层连接
	auth     statistic.Authenticator // 用来认证用户
	user     statistic.User          // 客户端连接用户
	hash     string                  // 数据包 hash
	metadata *tunnel.Metadata        // 请求目标地址信息
	ip       string                  // 客户端连接 ip
}

func (c *InboundConn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *InboundConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	atomic.AddUint64(&c.sent, uint64(n))
	c.user.AddTraffic(n, 0) // 记录该用户写入的流量
	return n, err
}

func (c *InboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddUint64(&c.recv, uint64(n))
	c.user.AddTraffic(0, n) // 记录该用户读取的流量
	return n, err
}

func (c *InboundConn) Close() error {
	log.Info("user", c.hash, "from", c.Conn.RemoteAddr(), "tunneling to", c.metadata.Address, "closed",
		"sent:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), "recv:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}

/*
*
+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+
*/
func (c *InboundConn) Auth() error {
	userHash := [56]byte{}
	n, err := c.Conn.Read(userHash[:])
	if err != nil || n != 56 {
		return common.NewError("failed to read hash").Base(err)
	}

	// 验证是否是合法用户
	valid, user := c.auth.AuthUser(string(userHash[:]))
	if !valid {
		return common.NewError("invalid hash:" + string(userHash[:]))
	}
	c.hash = string(userHash[:]) // 将整个字节数组转换为切片，然后转换为字符串
	c.user = user

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return common.NewError("failed to parse host:" + c.Conn.RemoteAddr().String()).Base(err)
	}

	c.ip = ip
	ok := user.AddIP(ip)
	if !ok {
		return common.NewError("ip limit reached")
	}

	crlf := [2]byte{} // CRLF 占用2个字节
	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}

	c.metadata = &tunnel.Metadata{}
	// 读取目标地址信息
	if err := c.metadata.ReadFrom(c.Conn); err != nil {
		return err
	}

	_, err = io.ReadFull(c.Conn, crlf[:]) // 读取 CRLF 占用2个字节，后面的数据就是请求负载了
	if err != nil {
		return err
	}
	return nil
}

// Server is a trojan tunnel server
type Server struct {
	auth       statistic.Authenticator // 身份认证
	redir      *redirector.Redirector
	redirAddr  *tunnel.Address
	underlay   tunnel.Server
	connChan   chan tunnel.Conn       // trojan TCP连接通道
	muxChan    chan tunnel.Conn       // 多路复用连接通道
	packetChan chan tunnel.PacketConn // trojan UDP连接通道
	ctx        context.Context
	cancel     context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil { // Closing
			log.Error(common.NewError("trojan failed to accept conn").Base(err))
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			rewindConn := common.NewRewindConn(conn)
			rewindConn.SetBufferSize(128)
			defer rewindConn.StopBuffering()

			inboundConn := &InboundConn{
				Conn: rewindConn,
				auth: s.auth,
			}

			// auth() 方法解析 trojan 协议
			if err := inboundConn.Auth(); err != nil {
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				log.Warn(common.NewError("connection with invalid trojan header from " + rewindConn.RemoteAddr().String()).Base(err))
				s.redir.Redirect(&redirector.Redirection{
					RedirectTo:  s.redirAddr,
					InboundConn: rewindConn,
				})
				return
			}

			rewindConn.StopBuffering()
			switch inboundConn.metadata.Command {
			case Connect:
				if inboundConn.metadata.DomainName == "MUX_CONN" { // 多路复用
					s.muxChan <- inboundConn
					log.Debug("mux(r) connection")
				} else {
					s.connChan <- inboundConn
					log.Debug("normal trojan connection")
				}

			case Associate:
				s.packetChan <- &PacketConn{
					Conn: inboundConn,
				}
				log.Debug("trojan udp connection")
			case Mux:
				s.muxChan <- inboundConn
				log.Debug("mux connection")
			default:
				log.Error(common.NewError(fmt.Sprintf("unknown trojan command %d", inboundConn.metadata.Command)))
			}
		}(conn)
	}
}

// 让上一层协议获取当前层协议的连接
func (s *Server) AcceptConn(nextTunnel tunnel.Tunnel) (tunnel.Conn, error) {
	switch nextTunnel.(type) {
	case *mux.Tunnel: // 多路复用服务协议
		select {
		case t := <-s.muxChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	default:
		select {
		case t := <-s.connChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	}
}

// 支持向上层提供 UDP 包
func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case t := <-s.packetChan:
		return t, nil
	case <-s.ctx.Done():
		return nil, common.NewError("trojan client closed")
	}
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)

	// TODO replace this dirty code
	var auth statistic.Authenticator
	var err error
	if cfg.MySQL.Enabled {
		log.Debug("mysql enabled")
		auth, err = statistic.NewAuthenticator(ctx, mysql.Name)
	} else {
		log.Debug("auth by config file")
		auth, err = statistic.NewAuthenticator(ctx, memory.Name)
	}
	if err != nil {
		cancel()
		return nil, common.NewError("trojan failed to create authenticator")
	}

	if cfg.API.Enabled {
		go api.RunService(ctx, Name+"_SERVER", auth)
	}

	redirAddr := tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort)
	s := &Server{
		underlay:   underlay,
		auth:       auth,
		redirAddr:  redirAddr,
		connChan:   make(chan tunnel.Conn, 32),
		muxChan:    make(chan tunnel.Conn, 32),
		packetChan: make(chan tunnel.PacketConn, 32),
		ctx:        ctx,
		cancel:     cancel,
		redir:      redirector.NewRedirector(ctx),
	}

	if !cfg.DisableHTTPCheck { // HTTP 重定向地址
		redirConn, err := net.Dial("tcp", redirAddr.String())
		if err != nil {
			cancel()
			return nil, common.NewError("invalid redirect address. check your http server: " + redirAddr.String()).Base(err)
		}
		redirConn.Close()
	}

	go s.acceptLoop()
	log.Debug("trojan server created")
	return s, nil
}
