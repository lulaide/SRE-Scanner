from tools import *
import asyncio
import os
from urllib.parse import urlparse
from rich import print

sqlmap_scanner = sqlmap_wrapper.Sqlmap()
sstimap_scanner = sstimap_wrapper.SSTImap()
oneforall_scanner = oneforall_wrapper.OneForAll()

# 异步启动和检查所有依赖的服务
async def initialize_scanners():
    """启动所有需要后台服务的扫描器，例如 sqlmap API。"""
    print("正在初始化扫描器...")
    await sqlmap_scanner.start()
    # 可以在这里添加其他需要启动的服务
    print("扫描器初始化完成。")

async def shutdown_scanners():
    """停止所有后台服务。"""
    print("正在关闭扫描器服务...")
    await sqlmap_scanner.stop()
    print("扫描器服务已关闭。")



all_tools = [
    {
        "type": "function",
        "function": {
            "name": "scan_directory_fuzzing",
            "description": "使用 ffuf 对指定的 URL 进行目录和文件模糊测试。适用于发现隐藏的路径或文件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "要扫描的目标 URL，必须包含 'FUZZ' 关键字，例如 'http://example.com/FUZZ'。"
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "用于模糊测试的字典文件路径。如果未提供，将使用默认字典 '/usr/share/dirb/wordlists/common.txt'。"
                    },
                    "threads": {
                        "type": "integer",
                        "description": "扫描线程数，默认为 None。"
                    },
                    "match_codes": {
                        "type": "string",
                        "description": "匹配的 HTTP 状态码，例如 '200,302'。"
                    }
                },
                "required": ["target_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_sql_injection",
            "description": "使用 sqlmap 对指定的 URL 进行 SQL 注入漏洞扫描。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "要扫描的目标 URL，例如 'http://example.com/product.php?id=1'。"
                    },
                    "data": {
                        "type": "string",
                        "description": "用于 POST 请求的数据，例如 'username=admin&password=123'。如果提供此参数，将执行 POST 注入测试。"
                    },
                    "options": {
                        "type": "object",
                        "description": "SQLMap 扫描选项的字典，例如 {'level': 1, 'risk': 1, 'batch': True}。"
                    }
                },
                "required": ["target_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_template_injection",
            "description": "使用 sstimap 对指定的 URL 进行服务器端模板注入 (SSTI) 漏洞扫描。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "要扫描的目标 URL，例如 'http://example.com/profile?name=guest'。"
                    },
                    "extra_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "传递给 SSTImap 的额外参数列表。"
                    }
                },
                "required": ["target_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_subdomain_enumeration",
            "description": "使用 OneForAll 对指定的主机进行子域名枚举。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_host": {
                        "type": "string",
                        "description": "要进行子域名枚举的目标主机名，例如 'example.com'。"
                    },
                    "extra_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "传递给 OneForAll 的额外参数列表。"
                    }
                },
                "required": ["target_host"]
            }
        }
    }
]

# 定义异步扫描函数

def get_host_from_url(url):
    """从 URL 中提取主机名，用于生成输出目录"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname or parsed_url.netloc
        # 移除可能的端口号和特殊字符，只保留主机名
        if host:
            host = host.split(':')[0].replace('.', '_').replace('-', '_')
            return host
        else:
            return "unknown_host"
    except Exception:
        return "unknown_host"

def get_output_dir(target):
    """生成基于目标的输出目录路径"""
    # 确保 test 目录存在
    base_dir = "test"
    os.makedirs(base_dir, exist_ok=True)
    
    # 对于 URL，提取主机名；对于主机名，直接使用
    if target.startswith(('http://', 'https://')):
        host = get_host_from_url(target)
    else:
        host = target.replace('.', '_').replace('-', '_')
    
    output_dir = os.path.join(base_dir, host)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

async def scan_directory_fuzzing(target_url, wordlist=None, threads=None, match_codes=None):
    """使用 ffuf 进行目录和文件模糊测试"""
    output_dir = get_output_dir(target_url)
    return await ffuf_wrapper.scan(
        url=target_url,
        output_dir=output_dir,
        wordlist=wordlist or "/usr/share/dirb/wordlists/common.txt",
        threads=threads,
        match_codes=match_codes
    )

async def scan_sql_injection(target_url, data=None, options=None):
    """使用 sqlmap 进行 SQL 注入扫描，自动管理 API 服务"""
    output_dir = get_output_dir(target_url)
    
    # sqlmap 需要特殊处理：启动 API 服务
    if not hasattr(sqlmap_scanner, 'process') or sqlmap_scanner.process is None:
        print("启动 SQLMap API 服务...")
        await sqlmap_scanner.start()
        await asyncio.sleep(5)  # 等待服务启动
    
    try:
        result = await sqlmap_scanner.scan(
            url=target_url,
            output_dir=output_dir,
            data=data,
            options=options
        )
        return result
    except Exception as e:
        print(f"[red]SQLMap 扫描出错: {e}[/red]")
        # 如果扫描出错，返回空结果
        await sqlmap_scanner.stop()
        return []

async def scan_template_injection(target_url, extra_args=None):
    """使用 sstimap 进行服务器端模板注入扫描"""
    output_dir = get_output_dir(target_url)
    return await sstimap_scanner.scan(
        url=target_url,
        output_dir=output_dir,
        extra_args=extra_args
    )

async def scan_subdomain_enumeration(target_host, extra_args=None):
    """使用 OneForAll 进行子域名枚举"""
    output_dir = get_output_dir(target_host)
    return await oneforall_scanner.scan(
        domain=target_host,
        output_dir=output_dir,
        extra_args=extra_args
    )

# 将函数名映射到实际的异步扫描函数
function_map = {
    "scan_directory_fuzzing": scan_directory_fuzzing,
    "scan_sql_injection": scan_sql_injection,
    "scan_template_injection": scan_template_injection,
    "scan_subdomain_enumeration": scan_subdomain_enumeration,
}