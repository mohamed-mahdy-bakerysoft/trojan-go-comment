package memory

import (
	"github.com/p4gefau1t/trojan-go/config"
)

type Config struct {
	Passwords []string `json:"password" yaml:"password"`
}

// 模块加载时自动执行
func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{}
	})
}
