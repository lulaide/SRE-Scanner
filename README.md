# SRE-Scanner
## 项目介绍
SRE-Scanner 是一个用于检测系统中常见渗透测试工具的脚本。它可以帮助安全研究人员快速识别可用的工具，从而提高渗透测试的效率。

## 功能
- [ ] 对于用户提供的ip/域名/端口，进行自动资产探寻
- [ ] 对扫描到的端口进行服务识别 (识别常见的服务, 如redis mysql ssh ftp 以及web服务)
- [ ] 可对一些常见到的数据库中间件 ssh ftp等服务进行自动密码爆破
- [ ] 可利用网上公开的 poc 文件库，对资产进行自动漏洞扫描，并输出/存储扫描到的漏洞
- [ ] 为命令行工具加上用 --help 查看使用方法的功能
- [ ] AI 功能

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
