package proxy

import (
	"context"

	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

// Trojan-Go将所有协议抽象为隧道，每个隧道可能提供客户端，负责发送；也可能提供服务端，负责接受；或者两者皆提供。自定义协议栈即自定义隧道的堆叠方式
// 自定义协议栈的工作方式是，定义树/链上节点并分别它们起名（tag）并添加配置，然后使用tag组成的有向路径，描述这棵树/链
type Node struct {
	Name       string // 协议 tag
	Next       map[string]*Node
	IsEndpoint bool
	context.Context
	tunnel.Server
	tunnel.Client
}

// 通过名称构建一个新的协议节点
func (n *Node) BuildNext(name string) *Node {
	if next, found := n.Next[name]; found {
		return next
	}
	t, err := tunnel.GetTunnel(name)
	if err != nil {
		log.Fatal(err)
	}
	s, err := t.NewServer(n.Context, n.Server) // 这里会建立服务协议栈
	if err != nil {
		log.Fatal(err)
	}
	newNode := &Node{ // 新建一个协议服务节点
		Name:    name,
		Next:    make(map[string]*Node),
		Context: n.Context,
		Server:  s,
	}
	n.Next[name] = newNode
	return newNode
}

// 通过一个原有的协议节点来构建协议栈
func (n *Node) LinkNextNode(next *Node) *Node {
	if next, found := n.Next[next.Name]; found {
		return next
	}
	n.Next[next.Name] = next
	t, err := tunnel.GetTunnel(next.Name)
	if err != nil {
		log.Fatal(err)
	}
	s, err := t.NewServer(next.Context, n.Server) // context of the child nodes have been initialized
	if err != nil {
		log.Fatal(err)
	}
	next.Server = s
	return next
}

// 深度递归获取自定义协议栈所有协议节点
func FindAllEndpoints(root *Node) []tunnel.Server {
	list := make([]tunnel.Server, 0)
	if root.IsEndpoint || len(root.Next) == 0 {
		list = append(list, root.Server)
	}
	for _, next := range root.Next {
		list = append(list, FindAllEndpoints(next)...)
	}
	return list
}

// CreateClientStack create client tunnel stacks from lists
func CreateClientStack(ctx context.Context, clientStack []string) (tunnel.Client, error) {
	var client tunnel.Client
	for _, name := range clientStack {
		t, err := tunnel.GetTunnel(name)
		if err != nil {
			return nil, err
		}
		client, err = t.NewClient(ctx, client) // 初始化出站协议栈客户端
		if err != nil {
			return nil, err
		}
	}
	return client, nil // 返回串联的出站客户端
}

// CreateServerStack create server tunnel stack from list
func CreateServerStack(ctx context.Context, serverStack []string) (tunnel.Server, error) {
	var server tunnel.Server
	for _, name := range serverStack {
		t, err := tunnel.GetTunnel(name)
		if err != nil {
			return nil, err
		}
		server, err = t.NewServer(ctx, server) // 初始化入站协议服务端
		if err != nil {
			return nil, err
		}
	}
	return server, nil // 返回串联的入站服务端
}
