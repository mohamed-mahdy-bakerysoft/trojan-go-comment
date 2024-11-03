# trojan-go一键二合一脚本

项目地址 https://github.com/p4gefau1t/trojan-go

- trojan-go 多路复用，降低延迟，提升并发性能

- trojan-go 一键脚本支持 CDN 流量中转等

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/lzh06550107/trojan-go-comment/master/install/trojan-go_install.sh)"
```

## 安装步骤

### 注意

1、系统支持 centos7+/debian9+/ubuntu16+

2、域名解析到 VPS 需要间生效，建议留 10 分钟，用 cloudflare 解析，能良好支持 TLS；

3、脚本自动续签 https 证书；

4、自动配置伪装网站，位于 /usr/share/nginx/html/ 目录下，可自行替换其中内容；

5、trojan 不能用 CDN，不要开启 CDN；

6、如果你在用谷歌云需要注意防火墙出入站规则设置并给 80 和 443 访问权限。

## trojan-go 常用操作


