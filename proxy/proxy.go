package proxy

import (
	"context"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

const Name = "PROXY"

const (
	MaxPacketSize = 1024 * 8 // UDP包大小 8k
)

// Proxy relay connections and packets
// Proxy 中继连接和数据包
/**
1. 代理服务器：这个结构体通常用于实现一个代理服务器，可以在源服务器和目标客户端之间中继数据。
2. 连接管理：sources 和 sink 字段可以帮助管理与多个源和目标的连接，从而实现复杂的数据流和处理逻辑。
3. 生命周期控制：通过上下文和取消函数，可以优雅地管理代理的启动和停止过程。
*/
type Proxy struct {
	// 用于存储多个协议服务的入站连接，代理可以从这些协议接收数据
	sources []tunnel.Server
	// 代理连接目标客户端出站连接，代理通过这些协议将数据转发到的目标服务器(已经创建好协议栈)
	sink tunnel.Client
	// 用于控制代理的生命周期。通过上下文，代理可以管理超时、取消信号以及传递请求范围内的值。上下文也可以帮助协调 goroutine 的运行
	ctx context.Context
	// 这是一个函数，可以用来取消上下文 ctx。当代理需要停止工作时，可以调用这个函数来终止所有与上下文相关联的操作
	cancel context.CancelFunc
}

// Run 启动代理的简单方法
func (p *Proxy) Run() error {
	p.relayConnLoop()   // TCP 连接中继
	p.relayPacketLoop() // UDP 连接中继
	// p.ctx.Done() 返回一个通道，当上下文被取消时，这个通道会接收到一个信号。这样可以优雅地停止 Run 方法的执行，确保所有的 goroutine 在停止时都有机会完成其操作
	<-p.ctx.Done() // 阻塞
	return nil
}

// Close 停止代理
func (p *Proxy) Close() error {
	p.cancel() // 取消上下文，停止所有操作
	p.sink.Close()
	for _, source := range p.sources {
		source.Close()
	}
	return nil
}

// 这个调用表示启动一个连接中继循环，通常用于处理来自源服务器的连接请求，并将其 TCP 数据包转发到目标客户端
// 1. 连接中继：这个方法实现了从源服务器到目标客户端的连接中继，使得数据可以在它们之间自由流动。
// 2. 并发处理：通过 goroutine 并发处理多个连接，使代理能够高效地处理流量。
func (p *Proxy) relayConnLoop() {
	// 循环遍历所有协议服务栈，针对每个协议服务栈启动一个新的 goroutine
	for _, source := range p.sources {
		go func(source tunnel.Server) {
			for {
				// 1. 接受连接
				// 尝试接受一个新的连接。如果失败，则检查上下文是否已取消，若是则退出循环
				inbound, err := source.AcceptConn(nil)
				if err != nil {
					// select 用于等待多个通道操作，其中至少一个通道准备好时会执行相应的代码块。在这里，它用于监听上下文的取消信号
					select {
					case <-p.ctx.Done(): // 阻塞
						log.Debug("exiting")
						return // 如果检查上下文已取消，若是则退出循环
					default: // default 是空的，表示如果上下文没有被取消，则继续执行后续代码，所以，不会阻塞
					}
					log.Error(common.NewError("failed to accept connection").Base(err))
					continue
				}
				// 2. 处理连接
				// 启动另一个 goroutine 来处理接受到的连接。使用 defer inbound.Close() 确保在函数退出时关闭连接
				go func(inbound tunnel.Conn) {
					defer inbound.Close()
					// 尝试建立与目标客户端的出站连接
					outbound, err := p.sink.DialConn(inbound.Metadata().Address, nil)
					if err != nil {
						log.Error(common.NewError("proxy failed to dial connection").Base(err))
						return
					}
					defer outbound.Close()
					// 定义一个 errChan 通道来收集错误
					errChan := make(chan error, 2)
					copyConn := func(a, b net.Conn) {
						_, err := io.Copy(a, b)
						errChan <- err
					}
					// 两个连接之间转发数据
					go copyConn(inbound, outbound)
					go copyConn(outbound, inbound)
					// 使用 select 等待 errChan 中的错误或上下文的取消信号，这里如果都没有获取消息，则阻塞
					select {
					case err = <-errChan:
						if err != nil { // 如果数据转发存在错误，则记录错误，结束连接中继
							log.Error(err)
						}
					case <-p.ctx.Done(): // 如果收到上下文的取消信号，则结束连接中继
						log.Debug("shutting down conn relay")
						return
					}
					log.Debug("conn relay ends")
				}(inbound)
			}
		}(source)
	}
}

// 这个调用启动一个数据包中继循环，负责在源服务器和目标客户端之间转发 UDP 数据包
func (p *Proxy) relayPacketLoop() {
	for _, source := range p.sources {
		go func(source tunnel.Server) {
			for {
				inbound, err := source.AcceptPacket(nil)
				if err != nil {
					select {
					case <-p.ctx.Done():
						log.Debug("exiting")
						return
					default:
					}
					log.Error(common.NewError("failed to accept packet").Base(err))
					continue
				}
				go func(inbound tunnel.PacketConn) {
					defer inbound.Close()
					outbound, err := p.sink.DialPacket(nil)
					if err != nil {
						log.Error(common.NewError("proxy failed to dial packet").Base(err))
						return
					}
					defer outbound.Close()
					errChan := make(chan error, 2)
					copyPacket := func(a, b tunnel.PacketConn) {
						for {
							buf := make([]byte, MaxPacketSize)
							n, metadata, err := a.ReadWithMetadata(buf)
							if err != nil {
								errChan <- err
								return
							}
							if n == 0 {
								errChan <- nil
								return
							}
							_, err = b.WriteWithMetadata(buf[:n], metadata)
							if err != nil {
								errChan <- err
								return
							}
						}
					}
					go copyPacket(inbound, outbound)
					go copyPacket(outbound, inbound)
					select {
					case err = <-errChan:
						if err != nil {
							log.Error(err)
						}
					case <-p.ctx.Done():
						log.Debug("shutting down packet relay")
					}
					log.Debug("packet relay ends")
				}(inbound)
			}
		}(source)
	}
}

// 提供了一种方便的方式来创建和初始化 Proxy 实例。通过传递上下文和取消函数，可以确保代理能够有效地管理其生命周期，并在需要时优雅地停止
func NewProxy(ctx context.Context, cancel context.CancelFunc, sources []tunnel.Server, sink tunnel.Client) *Proxy {
	return &Proxy{
		sources: sources, // 入站协议服务
		sink:    sink,    // 出站请求服务，已经构建协议栈
		ctx:     ctx,
		cancel:  cancel,
	}
}

// 代理创建器，ctx中包含配置
type Creator func(ctx context.Context) (*Proxy, error)

// 配置名称和代理创建器映射
var creators = make(map[string]Creator)

// 注册配置名称和代理创建器
func RegisterProxyCreator(name string, creator Creator) {
	creators[name] = creator
}

// NewProxyFromConfigData 根据传入的配置数据（以 JSON 或 YAML 格式）创建并返回一个新的 Proxy 实例
func NewProxyFromConfigData(data []byte, isJSON bool) (*Proxy, error) {
	// create a unique context for each proxy instance to avoid duplicated authenticator
	// 为每个代理实例创建一个唯一的上下文，以避免认证信息重复
	ctx := context.WithValue(context.Background(), Name+"_ID", rand.Int())
	var err error
	if isJSON {
		ctx, err = config.WithJSONConfig(ctx, data)
		if err != nil {
			return nil, err
		}
	} else {
		ctx, err = config.WithYAMLConfig(ctx, data)
		if err != nil {
			return nil, err
		}
	}
	// 用此函数后进行类型断言，以获取具体类型的数据
	cfg := config.FromContext(ctx, Name).(*Config)
	create, ok := creators[strings.ToUpper(cfg.RunType)] // 获取该类型的工厂
	if !ok {
		return nil, common.NewError("unknown proxy type: " + cfg.RunType)
	}
	log.SetLogLevel(log.LogLevel(cfg.LogLevel)) // 设置日志层级
	if cfg.LogFile != "" {
		file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, common.NewError("failed to open log file").Base(err)
		}
		log.SetOutput(file)
	}
	return create(ctx) // 根据上下文中的配置创建代理对象，如 client/server
}
