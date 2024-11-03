package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/redirector"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/tls/fingerprint"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
	"github.com/p4gefau1t/trojan-go/tunnel/websocket"
)

// Server is a tls server
type Server struct {
	fallbackAddress    *tunnel.Address // 指服务端TLS握手失败时，trojan-go将该连接重定向到该地址
	verifySNI          bool            // 表示客户端(client/nat/forward)是否校验服务端提供的证书合法性
	sni                string          // 指的是TLS客户端请求中的服务器名字段，一般和证书的Common Name相同
	alpn               []string        // 为TLS的应用层协议协商指定协议
	PreferServerCipher bool            // 客户端是否偏好选择服务端在协商中提供的密码学套件
	keyPair            []tls.Certificate
	keyPairLock        sync.RWMutex // 操作证书对的读写锁
	httpResp           []byte       // 指服务端TLS握手失败时，明文发送的原始数据（原始TCP数据）
	cipherSuite        []uint16     // TLS使用的密码学套件
	sessionTicket      bool
	curve              []tls.CurveID    // 指定TLS在ECDHE中偏好使用的椭圆曲线
	keyLogger          io.WriteCloser   // TLS密钥日志的文件路径
	connChan           chan tunnel.Conn // trojan 协议层通道
	wsChan             chan tunnel.Conn // websocket 协议层通道
	redir              *redirector.Redirector
	ctx                context.Context
	cancel             context.CancelFunc
	underlay           tunnel.Server // 底层服务
	nextHTTP           int32         // 上一层协议是否支持 http
	portOverrider      map[string]int
}

func (s *Server) Close() error {
	s.cancel()
	if s.keyLogger != nil {
		s.keyLogger.Close()
	}
	return s.underlay.Close()
}

func isDomainNameMatched(pattern string, domainName string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		domainPrefixLen := len(domainName) - len(suffix) - 1
		return strings.HasSuffix(domainName, suffix) && domainPrefixLen > 0 && !strings.Contains(domainName[:domainPrefixLen], ".")
	}
	return pattern == domainName
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{}) // 返回下一层协议的连接
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Fatal(common.NewError("transport accept error" + err.Error()))
			}
			return // 出错结束循环
		}
		go func(conn net.Conn) {
			tlsConfig := &tls.Config{
				CipherSuites:             s.cipherSuite,
				PreferServerCipherSuites: s.PreferServerCipher,
				SessionTicketsDisabled:   !s.sessionTicket,
				NextProtos:               s.alpn,
				KeyLogWriter:             s.keyLogger,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					s.keyPairLock.RLock()
					defer s.keyPairLock.RUnlock()
					// 是TLS客户端请求中的服务器名字段，一般和证书的Common Name相同
					sni := s.keyPair[0].Leaf.Subject.CommonName
					// 证书支持的所有 DNS 名称。这些名称通常用于验证 TLS 连接中主机的合法性
					dnsNames := s.keyPair[0].Leaf.DNSNames
					if s.sni != "" {
						sni = s.sni
					}
					matched := isDomainNameMatched(sni, hello.ServerName)
					for _, name := range dnsNames {
						if isDomainNameMatched(name, hello.ServerName) {
							matched = true
							break
						}
					}
					// 表示客户端(client/nat/forward)是否校验服务端提供的证书合法性
					if s.verifySNI && !matched {
						return nil, common.NewError("sni mismatched: " + hello.ServerName + ", expected: " + s.sni)
					}
					return &s.keyPair[0], nil
				},
			}

			// ------------------------ WAR ZONE ----------------------------

			handshakeRewindConn := common.NewRewindConn(conn)
			handshakeRewindConn.SetBufferSize(2048)

			// 使用 tls.Server 函数将 handshakeRewindConn 包装为一个 TLS 连接，并传入 TLS 配置 tlsConfig。这个配置包含证书、私钥和其他 TLS 参数
			tlsConn := tls.Server(handshakeRewindConn, tlsConfig)
			// 调用 tlsConn.Handshake() 方法执行 TLS 握手过程。这是建立安全连接的重要步骤，在此过程中，双方会协商加密算法、生成会话密钥等
			err = tlsConn.Handshake()
			handshakeRewindConn.StopBuffering()

			if err != nil {
				if strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
					// not a valid tls client hello
					handshakeRewindConn.Rewind() // 重置缓冲区索引
					log.Error(common.NewError("failed to perform tls handshake with " + tlsConn.RemoteAddr().String() + ", redirecting").Base(err))
					switch {
					case s.fallbackAddress != nil:
						// 重定向
						s.redir.Redirect(&redirector.Redirection{
							InboundConn: handshakeRewindConn,
							RedirectTo:  s.fallbackAddress,
						})
					case s.httpResp != nil:
						handshakeRewindConn.Write(s.httpResp) // 使用默认响应文件内容
						handshakeRewindConn.Close()
					default:
						handshakeRewindConn.Close()
					}
				} else {
					// in other cases, simply close it
					tlsConn.Close()
					log.Error(common.NewError("tls handshake failed").Base(err))
				}
				return
			}

			log.Info("tls connection from", conn.RemoteAddr())
			state := tlsConn.ConnectionState() // 返回有关连接的基本 TLS 详细信息
			log.Trace("tls handshake", tls.CipherSuiteName(state.CipherSuite), state.DidResume, state.NegotiatedProtocol)

			// we use a real http header parser to mimic a real http server
			// 我们使用真实的 http 标头解析器来模拟真实的 http 服务器
			rewindConn := common.NewRewindConn(tlsConn)
			rewindConn.SetBufferSize(1024)
			r := bufio.NewReader(rewindConn)
			httpReq, err := http.ReadRequest(r)
			rewindConn.Rewind() // 重置缓冲区索引
			rewindConn.StopBuffering()
			if err != nil {
				// this is not a http request. pass it to trojan protocol layer for further inspection
				s.connChan <- &transport.Conn{
					Conn: rewindConn,
				}
			} else {
				// 如果 tls 的上一层协议是 websocket 则会设置 nextHTTP = 1
				if atomic.LoadInt32(&s.nextHTTP) != 1 {
					// there is no websocket layer waiting for connections, redirect it
					log.Error("incoming http request, but no websocket server is listening")
					s.redir.Redirect(&redirector.Redirection{
						InboundConn: rewindConn,
						RedirectTo:  s.fallbackAddress,
					})
					return
				}
				// this is a http request, pass it to websocket protocol layer
				log.Debug("http req: ", httpReq)
				s.wsChan <- &transport.Conn{
					Conn: rewindConn,
				}
			}
		}(conn)
	}
}

// 让上一层协议获取当前层协议的连接
func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	// 如果 tls 的上一层协议是 websocket 则应该从 wsChan 通道获取连接
	if _, ok := overlay.(*websocket.Tunnel); ok {
		atomic.StoreInt32(&s.nextHTTP, 1)
		log.Debug("next proto http")
		// websocket overlay
		select {
		case conn := <-s.wsChan:
			return conn, nil
		case <-s.ctx.Done():
			return nil, common.NewError("transport server closed")
		}
	}
	// trojan overlay // 如果 tls 的上一层协议是 trojan 则应该从 connChan 通道获取连接
	select {
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

// 是一个用于监测 TLS 证书和私钥文件是否有变化的循环。这个函数会定期读取指定的密钥和证书文件，并检查它们的内容是否发生变化。如果发生变化，则加载新的密钥对
func (s *Server) checkKeyPairLoop(checkRate time.Duration, keyPath string, certPath string, password string) {
	var lastKeyBytes, lastCertBytes []byte
	// 轮询检查的时间间隔
	ticker := time.NewTicker(checkRate)

	for {
		log.Debug("checking cert...")
		keyBytes, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Error(common.NewError("tls failed to check key").Base(err))
			continue
		}
		certBytes, err := ioutil.ReadFile(certPath)
		if err != nil {
			log.Error(common.NewError("tls failed to check cert").Base(err))
			continue
		}
		if !bytes.Equal(keyBytes, lastKeyBytes) || !bytes.Equal(lastCertBytes, certBytes) {
			log.Info("new key pair detected")
			keyPair, err := loadKeyPair(keyPath, certPath, password)
			if err != nil {
				log.Error(common.NewError("tls failed to load new key pair").Base(err))
				continue
			}
			s.keyPairLock.Lock()
			s.keyPair = []tls.Certificate{*keyPair}
			s.keyPairLock.Unlock()
			lastKeyBytes = keyBytes
			lastCertBytes = certBytes
		}

		select {
		case <-ticker.C: // 阻塞
			continue
		case <-s.ctx.Done():
			log.Debug("exiting")
			ticker.Stop()
			return
		}
	}
}

// 加载密钥证书
func loadKeyPair(keyPath string, certPath string, password string) (*tls.Certificate, error) {
	if password != "" {
		keyFile, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, common.NewError("failed to load key file").Base(err)
		}
		keyBlock, _ := pem.Decode(keyFile)
		if keyBlock == nil {
			return nil, common.NewError("failed to decode key file").Base(err)
		}
		decryptedKey, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err == nil {
			return nil, common.NewError("failed to decrypt key").Base(err)
		}

		certFile, err := ioutil.ReadFile(certPath)
		certBlock, _ := pem.Decode(certFile)
		if certBlock == nil {
			return nil, common.NewError("failed to decode cert file").Base(err)
		}

		keyPair, err := tls.X509KeyPair(certBlock.Bytes, decryptedKey)
		if err != nil {
			return nil, err
		}
		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return nil, common.NewError("failed to parse leaf certificate").Base(err)
		}

		return &keyPair, nil
	}
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, common.NewError("failed to load key pair").Base(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, common.NewError("failed to parse leaf certificate").Base(err)
	}
	return &keyPair, nil
}

// NewServer creates a tls layer server
func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)

	var fallbackAddress *tunnel.Address
	var httpResp []byte
	if cfg.TLS.FallbackPort != 0 {
		if cfg.TLS.FallbackHost == "" {
			cfg.TLS.FallbackHost = cfg.RemoteHost
			log.Warn("empty tls fallback address")
		}
		// 将这个TCP连接代理到本地 fallbackAddress 上运行的 HTTPS 服务
		fallbackAddress = tunnel.NewAddressFromHostPort("tcp", cfg.TLS.FallbackHost, cfg.TLS.FallbackPort)
		// 测试地址是否有效
		fallbackConn, err := net.Dial("tcp", fallbackAddress.String())
		if err != nil {
			return nil, common.NewError("invalid fallback address").Base(err)
		}
		fallbackConn.Close()
	} else {
		log.Warn("empty tls fallback port")
		// plain_http_response指服务端TLS握手失败时，明文发送的原始数据（原始TCP数据）。这个字段填入该文件路径。推荐使用fallback_port而不是该字段
		if cfg.TLS.HTTPResponseFileName != "" {
			httpRespBody, err := ioutil.ReadFile(cfg.TLS.HTTPResponseFileName)
			if err != nil {
				return nil, common.NewError("invalid response file").Base(err)
			}
			httpResp = httpRespBody
		} else {
			log.Warn("empty tls http response")
		}
	}

	// 加载证书
	keyPair, err := loadKeyPair(cfg.TLS.KeyPath, cfg.TLS.CertPath, cfg.TLS.KeyPassword)
	if err != nil {
		return nil, common.NewError("tls failed to load key pair")
	}

	var keyLogger io.WriteCloser
	// key_logTLS密钥日志的文件路径。如果填写则开启密钥日志
	if cfg.TLS.KeyLogPath != "" {
		log.Warn("tls key logging activated. USE OF KEY LOGGING COMPROMISES SECURITY. IT SHOULD ONLY BE USED FOR DEBUGGING.")
		file, err := os.OpenFile(cfg.TLS.KeyLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, common.NewError("failed to open key log file").Base(err)
		}
		keyLogger = file
	}

	var cipherSuite []uint16
	// cipherTLS使用的密码学套件
	if len(cfg.TLS.Cipher) != 0 {
		cipherSuite = fingerprint.ParseCipher(strings.Split(cfg.TLS.Cipher, ":"))
	}

	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		underlay:           underlay,
		fallbackAddress:    fallbackAddress,
		httpResp:           httpResp,
		verifySNI:          cfg.TLS.VerifyHostName,
		sni:                cfg.TLS.SNI,
		alpn:               cfg.TLS.ALPN,
		PreferServerCipher: cfg.TLS.PreferServerCipher,
		sessionTicket:      cfg.TLS.ReuseSession,
		connChan:           make(chan tunnel.Conn, 32),
		wsChan:             make(chan tunnel.Conn, 32),
		redir:              redirector.NewRedirector(ctx),
		keyPair:            []tls.Certificate{*keyPair},
		keyLogger:          keyLogger,
		cipherSuite:        cipherSuite,
		ctx:                ctx,
		cancel:             cancel,
	}

	go server.acceptLoop()
	if cfg.TLS.CertCheckRate > 0 {
		go server.checkKeyPairLoop(
			time.Second*time.Duration(cfg.TLS.CertCheckRate),
			cfg.TLS.KeyPath,
			cfg.TLS.CertPath,
			cfg.TLS.KeyPassword,
		)
	}

	log.Debug("tls server created")
	return server, nil
}
