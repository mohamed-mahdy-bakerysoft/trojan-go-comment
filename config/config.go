package config

import (
	"context"
	"encoding/json"

	"gopkg.in/yaml.v3"
)

var creators = make(map[string]Creator)

// Creator creates default config struct for a module
type Creator func() interface{}

// RegisterConfigCreator registers a config struct for parsing
func RegisterConfigCreator(name string, creator Creator) {
	name += "_CONFIG"
	creators[name] = creator
}

// 解析JSON格式数据
func parseJSON(data []byte) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for name, creator := range creators {
		config := creator()
		// 使用 json.Unmarshal 将 JSON 数据解析到 config 中
		if err := json.Unmarshal(data, config); err != nil {
			return nil, err
		}
		result[name] = config
	}
	return result, nil
}

// 解析YAML格式数据
func parseYAML(data []byte) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for name, creator := range creators {
		config := creator()
		// 使用 json.Unmarshal 将 YAML 数据解析到 config 中
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, err
		}
		result[name] = config
	}
	return result, nil
}

// WithJSONConfig 解析JSON格式的配置
func WithJSONConfig(ctx context.Context, data []byte) (context.Context, error) {
	var configs map[string]interface{}
	var err error
	configs, err = parseJSON(data)
	if err != nil {
		return ctx, err
	}
	// 将解析后的 JSON 配置数据存储到 Go 的上下文中
	for name, config := range configs {
		ctx = context.WithValue(ctx, name, config) // 各个协议的配置
	}
	return ctx, nil
}

// WithYAMLConfig 解析YAML格式的配置
func WithYAMLConfig(ctx context.Context, data []byte) (context.Context, error) {
	var configs map[string]interface{}
	var err error
	configs, err = parseYAML(data)
	if err != nil {
		return ctx, err
	}
	// 将解析后的 YAML 配置数据存储到 Go 的上下文中
	for name, config := range configs {
		ctx = context.WithValue(ctx, name, config)
	}
	return ctx, nil
}

func WithConfig(ctx context.Context, name string, cfg interface{}) context.Context {
	name += "_CONFIG"
	return context.WithValue(ctx, name, cfg)
}

// FromContext extracts config from a context
// 返回的是 interface{} 类型，这意味着你需要在调用此函数后进行类型断言，以获取具体类型的数据
func FromContext(ctx context.Context, name string) interface{} {
	// 调用上下文的 Value 方法，使用 name + "_CONFIG" 作为键，从上下文中获取相应的值
	return ctx.Value(name + "_CONFIG")
}
