#!/usr/bin/env python3
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
        url="http://example.com/FUZZ",
        wordlist="/path/to/wordlist.txt",
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

async def check_ffuf_availability() -> bool:
    """
    检查 'ffuf' 命令是否在系统的 PATH 中可用。
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "which", "ffuf",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        return process.returncode == 0
    except FileNotFoundError:
        return False

class FfufScanner:
    """
    一个用于运行 ffuf 扫描的异步封装类。
    """
    def __init__(self, ffuf_path: str = "ffuf"):
        """
        初始化 FfufScanner。

        Args:
            ffuf_path (str): ffuf 可执行文件的路径。默认为 'ffuf'，
                             假设它在系统的 PATH 中。
        """
        self.ffuf_path = ffuf_path

    async def scan(
        self,
        url: str,
        wordlist: str,
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
            FileNotFoundError: 如果找不到 ffuf 可执行文件。
        """
        if not await check_ffuf_availability():
            raise FileNotFoundError(
                "找不到 'ffuf' 命令。请确保它已安装并位于您的 PATH 中。"
            )

        # 构建命令列表
        cmd = [
            self.ffuf_path,
            "-u", url,
            "-w", wordlist,
            "-of", "json"  # 强制使用 JSON 输出以便解析
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
            # ffuf 的 JSON 输出包含两部分：配置和结果，由换行符分隔
            # 我们只关心包含实际结果的最后一行
            json_output = stdout.decode(errors='ignore').strip()
            if not json_output:
                return [] # 如果没有输出，返回空列表
            
            # 解析包含结果的 JSON 对象
            # ffuf 的 JSON 输出通常是 {"commandline": "...", "results": [...]}
            parsed_json = json.loads(json_output)
            return parsed_json.get("results", [])
            
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

# --- 示例用法 ---
async def example_run():
    """
    演示如何使用 FfufScanner 的示例函数。
    注意: 这个示例需要一个有效的 wordlist 才能运行。
    """
    print("--- FfufScanner 示例 ---")
    
    # 创建一个临时字典文件用于演示
    wordlist_path = "temp_wordlist.txt"
    with open(wordlist_path, "w") as f:
        f.write("admin\n")
        f.write("test\n")
        f.write("index.php\n")
        f.write(".git\n")

    scanner = FfufScanner()
    
    try:
        # 使用一个公开的测试网站进行演示
        # 注意: 未经授权的扫描是违法的。请仅在授权范围内使用。
        target_url = "http://testphp.vulnweb.com/FUZZ"
        
        print(f"\n[1] 正在扫描: {target_url}")
        
        results = await scanner.scan(
            url=target_url,
            wordlist=wordlist_path,
            match_codes="200,301,302,403",
            threads=20
        )
        
        if results:
            print("\n✅ 扫描完成，找到以下路径:")
            for res in results:
                print(
                    f"  - URL: {res['url']} | "
                    f"Status: {res['status']} | "
                    f"Length: {res['length']}"
                )
        else:
            print("\nℹ️ 扫描完成，未找到匹配的路径。")

    except FileNotFoundError as e:
        print(f"\n❌ 错误: {e}", file=sys.stderr)
    except FfufExecutionError as e:
        print(f"\n❌ Ffuf 执行错误: {e}", file=sys.stderr)
        print(f"  Stderr: {e.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"\n❌ 发生未知错误: {e}", file=sys.stderr)
    finally:
        # 清理临时文件
        import os
        if os.path.exists(wordlist_path):
            os.remove(wordlist_path)
        print("\n--- 示例结束 ---")


if __name__ == "__main__":
    # 运行示例
    asyncio.run(example_run())

