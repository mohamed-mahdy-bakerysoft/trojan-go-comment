package option

import "github.com/p4gefau1t/trojan-go/common"

// 定义选项处理器接口
type Handler interface {
	Name() string  // 处理器名称
	Handle() error // 处理器处理函数
	Priority() int // 处理器优先级
}

// 创建保存选项处理器的map
var handlers = make(map[string]Handler)

// 注册选项处理器到map中
func RegisterHandler(h Handler) {
	handlers[h.Name()] = h
}

// 弹出优先级最高的选项处理器
func PopOptionHandler() (Handler, error) {
	var maxHandler Handler = nil
	for _, h := range handlers {
		if maxHandler == nil || maxHandler.Priority() < h.Priority() {
			maxHandler = h
		}
	}
	if maxHandler == nil { // easy 选项处理器优先级最高
		return nil, common.NewError("no option left")
	}
	delete(handlers, maxHandler.Name())
	return maxHandler, nil
}
