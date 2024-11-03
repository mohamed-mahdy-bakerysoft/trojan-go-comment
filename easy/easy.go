package easy

import (
	"encoding/json"
	"flag"
	"net"
	"strconv"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/option"
	"github.com/p4gefau1t/trojan-go/proxy"
)

type easy struct {
	server   *bool
	client   *bool
	password *string
	local    *string
	remote   *string
	cert     *string
	key      *string
}

type ClientConfig struct {
	RunType    string   `json:"run_type"`
	LocalAddr  string   `json:"local_addr"`
	LocalPort  int      `json:"local_port"`
	RemoteAddr string   `json:"remote_addr"`
	RemotePort int      `json:"remote_port"`
	Password   []string `json:"password"`
}

type TLS struct {
	SNI  string `json:"sni"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type ServerConfig struct {
	RunType    string   `json:"run_type"`
	LocalAddr  string   `json:"local_addr"`
	LocalPort  int      `json:"local_port"`
	RemoteAddr string   `json:"remote_addr"`
	RemotePort int      `json:"remote_port"`
	Password   []string `json:"password"`
	TLS        `json:"ssl"`
}

func (o *easy) Name() string {
	return "easy"
}

func (o *easy) Handle() error {
	if !*o.server && !*o.client { // 必须指定 client 或者 server
		return common.NewError("empty")
	}
	if *o.password == "" {
		log.Fatal("empty password is not allowed")
	}
	log.Info("easy mode enabled, trojan-go will NOT use the config file")
	if *o.client {
		if *o.local == "" {
			log.Warn("client local addr is unspecified, using 127.0.0.1:1080")
			*o.local = "127.0.0.1:1080"
		}
		localHost, localPortStr, err := net.SplitHostPort(*o.local)
		if err != nil {
			log.Fatal(common.NewError("invalid local addr format:" + *o.local).Base(err))
		}
		remoteHost, remotePortStr, err := net.SplitHostPort(*o.remote)
		if err != nil {
			log.Fatal(common.NewError("invalid remote addr format:" + *o.remote).Base(err))
		}
		localPort, err := strconv.Atoi(localPortStr)
		if err != nil {
			log.Fatal(err)
		}
		remotePort, err := strconv.Atoi(remotePortStr)
		if err != nil {
			log.Fatal(err)
		}
		clientConfig := ClientConfig{ // 创建客户端配置
			RunType:    "client",   // 客户端角色
			LocalAddr:  localHost,  // 本地监听host
			LocalPort:  localPort,  // 本地端口
			RemoteAddr: remoteHost, // 远程host
			RemotePort: remotePort, // 远程端口
			Password: []string{ // 连接密码
				*o.password,
			},
		}
		clientConfigJSON, err := json.Marshal(&clientConfig) // 将 Go 数据结构编码为 JSON 格式
		common.Must(err)                                     // 是一种简化错误处理的模式，适用于需要立即终止程序的场景
		log.Info("generated config:")
		log.Info(string(clientConfigJSON))
		proxy, err := proxy.NewProxyFromConfigData(clientConfigJSON, true)
		if err != nil {
			log.Fatal(err)
		}
		// 启动代理
		if err := proxy.Run(); err != nil {
			log.Fatal(err)
		}
	} else if *o.server {
		if *o.remote == "" {
			log.Warn("server remote addr is unspecified, using 127.0.0.1:80")
			*o.remote = "127.0.0.1:80"
		}
		if *o.local == "" {
			log.Warn("server local addr is unspecified, using 0.0.0.0:443")
			*o.local = "0.0.0.0:443"
		}
		localHost, localPortStr, err := net.SplitHostPort(*o.local)
		if err != nil {
			log.Fatal(common.NewError("invalid local addr format:" + *o.local).Base(err))
		}
		remoteHost, remotePortStr, err := net.SplitHostPort(*o.remote)
		if err != nil {
			log.Fatal(common.NewError("invalid remote addr format:" + *o.remote).Base(err))
		}
		localPort, err := strconv.Atoi(localPortStr)
		if err != nil {
			log.Fatal(err)
		}
		remotePort, err := strconv.Atoi(remotePortStr)
		if err != nil {
			log.Fatal(err)
		}
		serverConfig := ServerConfig{
			RunType:    "server", // 服务端角色
			LocalAddr:  localHost,
			LocalPort:  localPort,
			RemoteAddr: remoteHost,
			RemotePort: remotePort,
			Password: []string{
				*o.password,
			},
			TLS: TLS{ // 证书
				Cert: *o.cert,
				Key:  *o.key,
			},
		}
		serverConfigJSON, err := json.Marshal(&serverConfig) // 将 Go 数据结构编码为 JSON 格式
		common.Must(err)
		log.Info("generated json config:")
		log.Info(string(serverConfigJSON))
		proxy, err := proxy.NewProxyFromConfigData(serverConfigJSON, true)
		if err != nil {
			log.Fatal(err)
		}
		if err := proxy.Run(); err != nil {
			log.Fatal(err)
		}
	}
	return nil
}

func (o *easy) Priority() int {
	return 50
}

func init() {
	option.RegisterHandler(&easy{
		server:   flag.Bool("server", false, "Run a trojan-go server"),
		client:   flag.Bool("client", false, "Run a trojan-go client"),
		password: flag.String("password", "", "Password for authentication"),
		remote:   flag.String("remote", "", "Remote address, e.g. 127.0.0.1:12345"),
		local:    flag.String("local", "", "Local address, e.g. 127.0.0.1:12345"),
		key:      flag.String("key", "server.key", "Key of the server"),
		cert:     flag.String("cert", "server.crt", "Certificates of the server"),
	})
}
