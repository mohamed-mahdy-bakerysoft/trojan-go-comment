package client

import (
	"context"

	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/proxy"
	"github.com/p4gefau1t/trojan-go/tunnel/adapter"
	"github.com/p4gefau1t/trojan-go/tunnel/http"
	"github.com/p4gefau1t/trojan-go/tunnel/mux"
	"github.com/p4gefau1t/trojan-go/tunnel/router"
	"github.com/p4gefau1t/trojan-go/tunnel/shadowsocks"
	"github.com/p4gefau1t/trojan-go/tunnel/simplesocks"
	"github.com/p4gefau1t/trojan-go/tunnel/socks"
	"github.com/p4gefau1t/trojan-go/tunnel/tls"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
	"github.com/p4gefau1t/trojan-go/tunnel/trojan"
	"github.com/p4gefau1t/trojan-go/tunnel/websocket"
)

const Name = "CLIENT"

// GenerateClientTree generate general outbound protocol stack
func GenerateClientTree(transportPlugin bool, muxEnabled bool, wsEnabled bool, ssEnabled bool, routerEnabled bool) []string {
	clientStack := []string{transport.Name}
	// 传输层插件的作用，是替代 tansport 隧道的 TLS 进行传输加密和混淆
	if !transportPlugin {
		clientStack = append(clientStack, tls.Name)
	}
	if wsEnabled { // 开启 Websocket 支持
		clientStack = append(clientStack, websocket.Name)
	}
	if ssEnabled { // 开启 shadowsocks
		clientStack = append(clientStack, shadowsocks.Name)
	}
	// 必须支持 trojan 协议
	clientStack = append(clientStack, trojan.Name)
	if muxEnabled { // 开启多路复用
		clientStack = append(clientStack, []string{mux.Name, simplesocks.Name}...)
	}
	if routerEnabled { // Trojan-Go 客户端内建一个简单实用的路由模块，以方便实现国内直连、海外代理等自定义路由功能。见 README
		clientStack = append(clientStack, router.Name)
	}
	return clientStack
}

// 模块加载时自动执行
func init() {
	// 即代理创建工厂
	proxy.RegisterProxyCreator(Name, func(ctx context.Context) (*proxy.Proxy, error) {
		// 从上下文中根据名称获取配置
		cfg := config.FromContext(ctx, Name).(*Config)
		adapterServer, err := adapter.NewServer(ctx, nil)
		if err != nil {
			return nil, err
		}
		// cancel 是一个函数，调用它将取消上下文 ctx
		// 这意味着所有依赖于这个上下文的操作（如 goroutine 或网络请求）都可以通过监听这个上下文的状态来优雅地退出
		ctx, cancel := context.WithCancel(ctx)

		/**
		go func() {
		    for {
		        select {
		        case <-ctx.Done(): // 检查上下文是否被取消
		            // 执行清理工作或返回
		            log.Println("Goroutine exiting")
		            return
		        default:
		            // 执行正常逻辑
		            log.Println("Working...")
		            time.Sleep(1 * time.Second) // 模拟工作
		        }
		    }
		}()
		*/

		// 创建根节点
		root := &proxy.Node{
			Name:       adapter.Name,
			Next:       make(map[string]*proxy.Node),
			IsEndpoint: false,
			Context:    ctx,
			Server:     adapterServer,
		}

		// 入站路径 adapter->http
		root.BuildNext(http.Name).IsEndpoint = true
		// 入站路径 adapter->socks5
		root.BuildNext(socks.Name).IsEndpoint = true

		// 出站路径
		// 生成出站协议栈 trojan->tls->transport
		clientStack := GenerateClientTree(cfg.TransportPlugin.Enabled, cfg.Mux.Enabled, cfg.Websocket.Enabled, cfg.Shadowsocks.Enabled, cfg.Router.Enabled)
		c, err := proxy.CreateClientStack(ctx, clientStack)
		if err != nil {
			cancel()
			return nil, err
		}
		// 获取入站协议栈
		s := proxy.FindAllEndpoints(root)
		return proxy.NewProxy(ctx, cancel, s, c), nil
	})
}
