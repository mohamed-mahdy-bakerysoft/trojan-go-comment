package client

import "github.com/p4gefau1t/trojan-go/config"

type MuxConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type WebsocketConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type RouterConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type ShadowsocksConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type TransportPluginConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type Config struct {
	Mux             MuxConfig             `json:"mux" yaml:"mux"`
	Websocket       WebsocketConfig       `json:"websocket" yaml:"websocket"`
	Router          RouterConfig          `json:"router" yaml:"router"`
	Shadowsocks     ShadowsocksConfig     `json:"shadowsocks" yaml:"shadowsocks"`
	TransportPlugin TransportPluginConfig `json:"transport_plugin" yaml:"transport-plugin"`
}

// 模块加载时自动执行
func init() {
	// new 是一个内置函数，用于分配内存并初始化值。它通常用于创建指向类型的指针
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(Config)
	})
}
