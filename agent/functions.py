from tools import *
import asyncio
import os
from urllib.parse import urlparse
from rich import print
import json
from httpx import AsyncClient

sqlmap_scanner = sqlmap_wrapper.Sqlmap()
sstimap_scanner = sstimap_wrapper.SSTImap()
oneforall_scanner = oneforall_wrapper.OneForAll()


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
    },
    {
        "type": "function",
        "function": {
            "name": "scan_port_scanning",
            "description": "使用 nmap 对指定的目标进行端口扫描，发现开放端口和运行的服务。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "要扫描的目标主机或IP地址，例如 '192.168.1.1' 或 'example.com'。"
                    },
                    "ports": {
                        "type": "string",
                        "description": "要扫描的端口范围，例如 '1-1000' 或 '22,80,443'。如果未提供，将使用默认的常用端口。"
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "扫描类型：'tcp' (TCP扫描，默认), 'udp' (UDP扫描), 'syn' (SYN扫描), 'fin' (FIN扫描)等。",
                        "enum": ["tcp", "udp", "syn", "fin", "xmas", "null", "ack"]
                    },
                    "service_detection": {
                        "type": "boolean",
                        "description": "是否启用服务版本检测。默认为 True。"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url_content",
            "description": "使用 httpx 异步获取指定 URL 的内容。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "要获取内容的目标 URL，例如 'http://example.com'。"
                    }
                },
                "required": ["url"]
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

async def scan_port_scanning(target, ports=None, scan_type="tcp", service_detection=False):
    """使用 python-nmap 进行端口扫描"""
    output_dir = get_output_dir(target)
    
    try:
        # 创建 nmap 对象
        nm = nmap.PortScanner()
        
        # 构建扫描参数
        nmap_args = ""
        
        # 设置扫描类型
        if scan_type == "tcp":
            nmap_args += "-sT "
        elif scan_type == "syn":
            nmap_args += "-sS "
        elif scan_type == "udp":
            nmap_args += "-sU "
        elif scan_type == "fin":
            nmap_args += "-sF "
        elif scan_type == "xmas":
            nmap_args += "-sX "
        elif scan_type == "null":
            nmap_args += "-sN "
        elif scan_type == "ack":
            nmap_args += "-sA "
        
        # 激进扫描模式
        
        if service_detection:
            nmap_args += "-sV "
        
        # 设置端口范围
        port_range = ports or "1-65535"
        
        print(f"[grey54]  开始对 {target} 进行端口扫描...")
        print(f"[grey54]  扫描参数: {nmap_args.strip()}")
        print(f"[grey54]  端口范围: {port_range}")
        
        # 执行扫描
        scan_result = nm.scan(target, port_range, arguments=nmap_args.strip())
        
        # 处理扫描结果
        results = []
        for host in nm.all_hosts():
            host_info = {
                "host": host,
                "hostname": nm[host].hostname() if nm[host].hostname() else "",
                "state": nm[host].state(),
                "open_ports": [],
                "os_info": {}
            }
            
            # 获取开放端口信息
            for protocol in nm[host].all_protocols():
                ports_list = nm[host][protocol].keys()
                for port in sorted(ports_list):
                    port_state = nm[host][protocol][port]['state']
                    if port_state == 'open':
                        port_info = {
                            "port": port,
                            "protocol": protocol,
                            "state": port_state,
                            "service": nm[host][protocol][port].get('name', ''),
                            "version": nm[host][protocol][port].get('version', ''),
                            "product": nm[host][protocol][port].get('product', ''),
                            "extrainfo": nm[host][protocol][port].get('extrainfo', '')
                        }
                        host_info["open_ports"].append(port_info)
            
            results.append(host_info)
        
        # 保存结果到文件
        output_file = os.path.join(output_dir, f"nmap_scan.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        
        print(f"[grey54]  扫描完成！结果已保存到: {output_file}")
        return results
        
    except Exception as e:
        print(f"[red]Nmap 扫描出错: {e}[/red]")
        return []

async def fetch_url_content(url):
    """使用 httpx 异步获取 URL 内容"""
    async with AsyncClient() as client:
        try:
            response = await client.get(url)
            if response.status_code == 200:
                return response.text
            else:
                print(f"[red]请求失败，状态码: {response.status_code}[/red]")
                return None
        except Exception as e:
            print(f"[red]请求出错: {e}[/red]")
            return None

# 将函数名映射到实际的异步扫描函数
function_map = {
    "scan_directory_fuzzing": scan_directory_fuzzing,
    "scan_sql_injection": scan_sql_injection,
    "scan_template_injection": scan_template_injection,
    "scan_subdomain_enumeration": scan_subdomain_enumeration,
    "scan_port_scanning": scan_port_scanning,
    "fetch_url_content": fetch_url_content
}


if __name__ == "__main__":
    async def main():
        result = await scan_port_scanning('192.168.100.200', ports='1-65535', scan_type='tcp', service_detection=False)
        print(result)
    asyncio.run(main())