//go:build api || full
// +build api full

//从 Go 1.17 开始，Go 引入了一种新的构建标签语法。这里使用 //go:build 语法来指定构建标签。
//逻辑或：api || full 表示只要 api 或 full 标签中的一个被激活，相关的代码就会被编译。

package build

import (
	_ "github.com/p4gefau1t/trojan-go/api/control"
	_ "github.com/p4gefau1t/trojan-go/api/service"
)
