# SRE-Scanner

## 项目介绍

SRE-Scanner 是一个用于检测系统中常见渗透测试工具的脚本。它可以帮助安全研究人员快速识别可用的工具，从而提高渗透测试的效率。

## 功能

- [x] 对于用户提供的ip/域名/端口，进行自动资产探寻
- [x] 对扫描到的端口进行服务识别 (识别常见的服务, 如redis mysql ssh ftp 以及web服务)
- [ ] 可对一些常见到的数据库中间件 ssh ftp等服务进行自动密码爆破
- [x] 可利用网上公开的 poc 文件库，对资产进行自动漏洞扫描，并输出/存储扫描到的漏洞
- [x] 为命令行工具加上用 --help 查看使用方法的功能
- [x] AI 功能

| **功能项** | **相关工具** |
| -----| ----- |
| 资产探寻| `nmap`, `dirb`, `ffuf`|
| 子域扫描| `oneforall` |
| 端口服务识别 | `nmap` |
| 服务密码爆破 | `hydra`|
| 自动漏洞扫描| `msfconsole` |

## 环境准备

- 克隆仓库和子模块

```bash
git clone --recurse-submodules https://github.com/lulaide/SRE-Scanner.git
```

- 更新子模块

```bash
git submodule update --recursive --remote
# git submodule update --recursive --init
```

- Conda 环境

```bash
conda create --name SRE-Scanner python=3.10
conda activate SRE-Scanner
pip install -r requirements.txt
```

- uv 环境

```bash
uv python install 3.10
uv venv
uv activate SRE-Scanner
uv pip install -r requirements.txt
```

- WebTree 环境

```bash
cd tools/module_WebTree
npm install
```

- 编译 go-poc

```bash
cd go-poc
go build
cd ../../../
```

## 使用方法

- 整个网站扫描，并运行 POC

```bash
❯ python main.py http://localhost:3000 --no-check
🔍 正在使用 WebTree 扫描: http://localhost:3000
🔬 已启用POC检测
✅ WebTree 扫描完成
✔️ 网站自动扫描完成。
⠇ WebTree 扫描完成
✅ WebTree 网站扫描完成

扫描结果:
[+] 找到 2 个插件
[+] 插件 file_match 加载成功
[+] 插件 header_match 加载成功
正在访问: http://localhost:3000
找到匹配的路径记录: 1 条
实际 MD5: bcc4933f81eff43e5d9bcc5b2828aa70
期望 MD5: bcc4933f81eff43e5d9bcc5b2828aa70
[+] MD5 匹配成功 - 检测到: grafana
正在访问: http://localhost:3000/
正在访问: http://localhost:3000/dashboards
正在访问: http://localhost:3000/playlists
正在访问: http://localhost:3000/alerting/list
正在访问: http://localhost:3000/login
正在访问: http://localhost:3000/user/password/send-reset-email
[*] 开始执行POC测试...
[*] 正在测试技术栈: gin
【成功】POC poc-yaml-grafana-default-password 执行成功，目标可能存在漏洞！
[*] 正在测试技术栈: grafana

爬取完成.
检测到的技术栈: [ 'gin', 'grafana' ]

=== POC测试结果汇总 ===
共发现 1 个潜在漏洞
```

- 注入点注入测试

```bash
python main.py -u http://localhost:4000/?name=1 --no-check
```

- 子域名，资产扫描

```bash
python main.py -h example.com --no-check
```
