package proxy

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/constant"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/option"
)

// Option 通过使用 type，你可以创建结构体、接口、数组、切片以及其他数据类型。定义新的类型有助于提高代码的可读性、可维护性和类型安全性
type Option struct {
	path *string
}

// Name 返回处理器名称
func (o *Option) Name() string {
	return Name
}

// 检测配置文件类型并读取配置数据
func detectAndReadConfig(file string) ([]byte, bool, error) {
	isJSON := false
	switch {
	case strings.HasSuffix(file, ".json"):
		isJSON = true
	case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
		isJSON = false
	default:
		log.Fatalf("unsupported config format: %s. use .yaml or .json instead.", file)
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, false, err
	}
	return data, isJSON, nil
}

// Handle Option 处理器的处理方法
func (o *Option) Handle() error {
	// 默认配置文件名称
	defaultConfigPath := []string{
		"config.json",
		"config.yml",
		"config.yaml",
	}

	isJSON := false
	var data []byte
	var err error

	switch *o.path {
	case "":
		log.Warn("no specified config file, use default path to detect config file")
		for _, file := range defaultConfigPath {
			log.Warn("try to load config from default path:", file)
			data, isJSON, err = detectAndReadConfig(file)
			if err != nil {
				log.Warn(err)
				continue
			}
			break
		}
	default:
		data, isJSON, err = detectAndReadConfig(*o.path)
		if err != nil {
			log.Fatal(err)
		}
	}

	if data != nil {
		log.Info("trojan-go", constant.Version, "initializing")
		proxy, err := NewProxyFromConfigData(data, isJSON) // 创建代理
		if err != nil {
			log.Fatal(err)
		}
		err = proxy.Run() // 启动代理
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Fatal("no valid config")
	return nil
}

func (o *Option) Priority() int {
	return -1
}

// 模块加载时自动运行
func init() {
	// 设置 config 选项
	option.RegisterHandler(&Option{
		path: flag.String("config", "", "Trojan-Go config filename (.yaml/.yml/.json)"),
	})
	option.RegisterHandler(&StdinOption{
		format:       flag.String("stdin-format", "disabled", "Read from standard input (yaml/json)"),
		suppressHint: flag.Bool("stdin-suppress-hint", false, "Suppress hint text"),
	})
}

type StdinOption struct {
	format       *string
	suppressHint *bool
}

func (o *StdinOption) Name() string {
	return Name + "_STDIN"
}

func (o *StdinOption) Handle() error {
	isJSON, e := o.isFormatJson()
	if e != nil {
		return e
	}

	if o.suppressHint == nil || !*o.suppressHint {
		fmt.Printf("Trojan-Go %s (%s/%s)\n", constant.Version, runtime.GOOS, runtime.GOARCH)
		if isJSON {
			fmt.Println("Reading JSON configuration from stdin.")
		} else {
			fmt.Println("Reading YAML configuration from stdin.")
		}
	}

	data, e := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if e != nil {
		log.Fatalf("Failed to read from stdin: %s", e.Error())
	}

	proxy, err := NewProxyFromConfigData(data, isJSON)
	if err != nil {
		log.Fatal(err)
	}
	err = proxy.Run()
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func (o *StdinOption) Priority() int {
	return 0
}

func (o *StdinOption) isFormatJson() (isJson bool, e error) {
	if o.format == nil {
		return false, common.NewError("format specifier is nil")
	}
	if *o.format == "disabled" {
		return false, common.NewError("reading from stdin is disabled")
	}
	return strings.ToLower(*o.format) == "json", nil
}
