package websocket

import (
	"bufio"
	"context"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/redirector"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

// Fake response writer
// Websocket ServeHTTP method uses Hijack method to get the ReadWriter
type fakeHTTPResponseWriter struct {
	http.Hijacker
	http.ResponseWriter

	ReadWriter *bufio.ReadWriter
	Conn       net.Conn
}

func (w *fakeHTTPResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.Conn, w.ReadWriter, nil
}

type Server struct {
	underlay  tunnel.Server
	hostname  string
	path      string
	enabled   bool // 开启 websocket
	redirAddr net.Addr
	redir     *redirector.Redirector
	ctx       context.Context
	cancel    context.CancelFunc
	timeout   time.Duration // 握手超时等待时间
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

// 让上一层协议获取当前层协议的连接
func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := s.underlay.AcceptConn(&Tunnel{})
	if err != nil {
		return nil, common.NewError("websocket failed to accept connection from underlying server")
	}
	if !s.enabled {
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: conn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("websocket is disabled. redirecting http request from " + conn.RemoteAddr().String())
	}
	rewindConn := common.NewRewindConn(conn)
	rewindConn.SetBufferSize(512)
	defer rewindConn.StopBuffering()
	rw := bufio.NewReadWriter(bufio.NewReader(rewindConn), bufio.NewWriter(rewindConn))
	req, err := http.ReadRequest(rw.Reader)
	if err != nil {
		log.Debug("invalid http request")
		rewindConn.Rewind()
		rewindConn.StopBuffering()
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: rewindConn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("not a valid http request: " + conn.RemoteAddr().String()).Base(err)
	}
	if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" || req.URL.Path != s.path {
		log.Debug("invalid http websocket handshake request")
		rewindConn.Rewind()
		rewindConn.StopBuffering()
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: rewindConn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("not a valid websocket handshake request: " + conn.RemoteAddr().String()).Base(err)
	}

	handshake := make(chan struct{})

	url := "wss://" + s.hostname + s.path
	origin := "https://" + s.hostname
	// 创建一个新的 WebSocket 配置对象。这个配置对象用于后续的 WebSocket 连接
	wsConfig, err := websocket.NewConfig(url, origin)
	if err != nil {
		return nil, common.NewError("failed to create websocket config").Base(err)
	}
	var wsConn *websocket.Conn
	ctx, cancel := context.WithCancel(s.ctx)

	wsServer := websocket.Server{
		Config: *wsConfig,
		Handler: func(conn *websocket.Conn) {
			wsConn = conn                              // store the websocket after handshaking
			wsConn.PayloadType = websocket.BinaryFrame // treat it as a binary websocket

			log.Debug("websocket obtained")
			handshake <- struct{}{}
			// this function SHOULD NOT return unless the connection is ended
			// or the websocket will be closed by ServeHTTP method
			<-ctx.Done() // 阻塞
			log.Debug("websocket closed")
		},
		Handshake: func(wsConfig *websocket.Config, httpRequest *http.Request) error {
			log.Debug("websocket url", httpRequest.URL, "origin", httpRequest.Header.Get("Origin"))
			return nil
		},
	}

	respWriter := &fakeHTTPResponseWriter{
		Conn:       conn,
		ReadWriter: rw,
	}
	go wsServer.ServeHTTP(respWriter, req) // ws 处理器

	select {
	case <-handshake:
		// time.After(s.timeout) 会返回一个通道，在指定的时间 s.timeout 后发送一个空的信号
	case <-time.After(s.timeout): // 握手超时等待
	}

	if wsConn == nil { // ws连接没有初始化，则握手失败
		cancel()
		return nil, common.NewError("websocket failed to handshake")
	}

	return &InboundConn{ // 返回入站连接对象
		OutboundConn: OutboundConn{
			tcpConn: conn,
			Conn:    wsConn,
		},
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// 不支持向上层提供 UDP 包
func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	return nil, common.NewError("not supported")
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	if cfg.Websocket.Enabled {
		if !strings.HasPrefix(cfg.Websocket.Path, "/") {
			return nil, common.NewError("websocket path must start with \"/\"")
		}
	}
	if cfg.RemoteHost == "" {
		log.Warn("empty websocket redirection hostname")
		cfg.RemoteHost = cfg.Websocket.Host
	}
	if cfg.RemotePort == 0 {
		log.Warn("empty websocket redirection port")
		cfg.RemotePort = 80
	}
	ctx, cancel := context.WithCancel(ctx)
	log.Debug("websocket server created")
	return &Server{
		enabled:   cfg.Websocket.Enabled,
		hostname:  cfg.Websocket.Host,
		path:      cfg.Websocket.Path,
		ctx:       ctx,
		cancel:    cancel,
		underlay:  underlay,
		timeout:   time.Second * time.Duration(rand.Intn(10)+5),
		redir:     redirector.NewRedirector(ctx),
		redirAddr: tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort),
	}, nil
}
