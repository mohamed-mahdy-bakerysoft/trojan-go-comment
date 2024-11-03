package main

import (
	"flag"
	// 在 Go 中，包可以包含一个 init 函数。当包被导入时，init 函数会自动执行。这对于一些需要在程序启动时进行初始化的包非常有用。
	_ "github.com/p4gefau1t/trojan-go/component"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/option"
)

func main() {
	flag.Parse() // 解析用户定义参数
	for {        // 按优先级循环处理各种配置来启动服务
		h, err := option.PopOptionHandler()
		if err != nil {
			// TODO 感觉提示词不对
			log.Fatal("invalid options")
		}
		err = h.Handle()
		if err == nil { // 没有符合的配置服务，则退出
			break
		}
	}
}
