package proxy

import "github.com/p4gefau1t/trojan-go/config"

type Config struct {
	RunType  string `json:"run_type" yaml:"run-type"`
	LogLevel int    `json:"log_level" yaml:"log-level"`
	LogFile  string `json:"log_file" yaml:"log-file"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		// 返回一个指向 Config 类型的指针，初始化 LogLevel 为 1
		return &Config{
			LogLevel: 1,
		}
	})
}
