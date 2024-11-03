package version

import (
	"flag"
	"fmt"
	"runtime"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/constant"
	"github.com/p4gefau1t/trojan-go/option"
)

// 版本配置选项
type versionOption struct {
	flag *bool
}

func (*versionOption) Name() string {
	return "version"
}

func (*versionOption) Priority() int {
	return 10
}

func (c *versionOption) Handle() error {
	if *c.flag { // 存在该选项，则为真
		fmt.Println("Trojan-Go", constant.Version)               // Trojan-Go 版本
		fmt.Println("Go Version:", runtime.Version())            // Go 版本
		fmt.Println("OS/Arch:", runtime.GOOS+"/"+runtime.GOARCH) // 操作系统和架构
		fmt.Println("Git Commit:", constant.Commit)              // git 提交
		fmt.Println("")
		fmt.Println("Developed by PageFault (p4gefau1t)")                           // 开发者信息
		fmt.Println("Licensed under GNU General Public License version 3")          // 开源证书
		fmt.Println("GitHub Repository:\thttps://github.com/p4gefau1t/trojan-go")   // git 仓库
		fmt.Println("Trojan-Go Documents:\thttps://p4gefau1t.github.io/trojan-go/") // Trojan-Go 文档
		return nil
	}
	return common.NewError("not set")
}

// 模块加载时自动加载
func init() {
	option.RegisterHandler(&versionOption{
		flag: flag.Bool("version", false, "Display version and help info"),
	})
}
