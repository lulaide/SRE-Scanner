"""
Ffuf 工具的异步 Python 封装库

本模块提供了一个 `FfufScanner` 类，用于以编程方式异步调用
`ffuf` 命令行工具。它简化了参数传递，并能自动解析 JSON 输出。

主要功能:
- 异步执行扫描，避免阻塞。
- 将 ffuf 参数映射为 Python 方法的参数。
- 自动解析 JSON 格式的扫描结果。
- 提供错误处理和 ffuf 可用性检查。

示例:
    scanner = FfufScanner()
    results = await scanner.scan(
        url="http://testphp.vulnweb.com/FUZZ",
        wordlist="/usr/share/dirb/wordlists/common.txt",
        match_codes="200,204,301,302"
    )
    for result in results:
        print(f"Found: {result['url']}")
"""
import asyncio
import json
import sys
from typing import List, Dict, Any, Optional


class FfufExecutionError(Exception):
    """当 ffuf 执行失败时抛出的自定义异常。"""
    def __init__(self, message, stderr):
        super().__init__(message)
        self.stderr = stderr



async def scan(
    url: str,
    output_dir: str,
    wordlist: str = "/usr/share/dirb/wordlists/common.txt",
    threads: Optional[int] = None,
    match_codes: Optional[str] = None,
    filter_size: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    extra_args: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    异步执行 ffuf 扫描。

    Args:
        url (str): 目标 URL，必须包含 'FUZZ' 关键字。
        wordlist (str): 字典文件路径。
        threads (Optional[int]): 扫描线程数 (-t)。
        match_codes (Optional[str]): 匹配的 HTTP 状态码 (-mc)，例如 "200,302"。
        filter_size (Optional[str]): 按大小过滤响应 (-fs)，例如 "123,0"。
        headers (Optional[Dict[str, str]]): 自定义 HTTP 请求头 (-H)。
        extra_args (Optional[List[str]]): 其他要传递给 ffuf 的原始参数。

    Returns:
        List[Dict[str, Any]]: ffuf 扫描结果的列表，每个结果是一个字典。

    Raises:
        FfufExecutionError: 如果 ffuf 执行失败或返回非零退出码。
    """
    file_path = f"{output_dir}/ffuf_output.json"
    # 构建命令列表
    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist,
        "-of", "json",
        "-o" , file_path
    ]

    if threads:
        cmd.extend(["-t", str(threads)])
    
    if match_codes:
        cmd.extend(["-mc", match_codes])
        
    if filter_size:
        cmd.extend(["-fs", filter_size])

    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    if extra_args:
        cmd.extend(extra_args)

    print(f"🚀 执行命令: {' '.join(cmd)}")

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        raise FfufExecutionError(
            f"Ffuf 执行失败，返回码: {process.returncode}",
            stderr.decode(errors='ignore')
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        results = []
        for result in data["results"]:
            filtered = {
                "key": result["input"]["FUZZ"],
                "status": result["status"],
                "size": result["length"],
            }
            results.append(filtered)
        return results
        
    except json.JSONDecodeError:
        raise FfufExecutionError(
            "解析 ffuf JSON 输出失败。",
            stdout.decode(errors='ignore')
        )
    except Exception as e:
        raise FfufExecutionError(
            f"处理 ffuf 输出时发生未知错误: {e}",
            stdout.decode(errors='ignore')
        )