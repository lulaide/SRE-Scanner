import asyncio
import re
from rich import print
from typing import Optional, Dict, List, Any

class SSTImapExecutionError(Exception):
    """当 SSTImap 执行失败时抛出的自定义异常。"""
    def __init__(self, message, stderr):
        super().__init__(message)
        self.stderr = stderr

class SSTImap:
    def __init__(self):
        self.sstimap_path = "tools/module_sstimap/sstimap.py"

    async def check(self) -> bool:
        process = await asyncio.create_subprocess_exec(
            "python", self.sstimap_path, "--help",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        if process.returncode != 0:
            print(f"SSTImap 子模块 {self.sstimap_path} 不可用。请检查路径。")
            return False
        return True
    
    async def scan(self, 
        url: str, 
        output_dir: str, 
        extra_args: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        异步执行 SSTImap 扫描。

        Args:
            url (str): 目标域名或 IP 地址。
            output_dir (str): 输出目录。
            extra_args (Optional[List[str]]): 其他要传递给 SSTImap 的原始参数。

        Returns:
            Optional[str]: SSTImap 扫描结果的字符串，或在失败时返回 None。

        Raises:
            SSTImapExecutionError: 如果 SSTImap 执行失败或返回非零退出码。
        """
        file_path = f"{output_dir}/sstimap_output.txt"
        
        # 构建命令列表
        cmd = [
            "python",
            self.sstimap_path,
            "-u", url,
        ]
        
        if extra_args:
            cmd.extend(extra_args)

        print(f"[grey54]  执行命令: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise SSTImapExecutionError(
                f"SSTImap 执行失败，返回码: {process.returncode}",
                stderr.decode()
            )
        else:
            # 解码并移除 ANSI 转义码和多余符号
            raw_results = stdout.decode().strip()
            # 正则表达式，用于移除 ANSI 颜色代码和 SSTImap 特定的状态符号
            ansi_escape = re.compile(r'(\x1b\[[0-9;]*[mK])|(\[92m\[\+\]\[0m)|(\[92m|\[0m)')
            results = ansi_escape.sub('', raw_results)
            
            try:
                start_marker = "SSTImap identified the following injection point:"
                end_marker = "Rerun SSTImap providing one of the following options"
                injection_info = []
                capturing = False
                for line in results.splitlines():
                    if start_marker in line:
                        capturing = True
                    
                    if capturing:
                        # 移除行首的空白字符
                        cleaned_line = line.lstrip()
                        injection_info.append(cleaned_line)

                    if end_marker in line:
                        # 移除包含结束标记的最后一行
                        if injection_info:
                            injection_info.pop()
                        capturing = False
                        break
        
                # 使用换行符重新拼接，并移除前后的多余空白
                output_text = "\n".join(injection_info).strip()
                with open(file_path, 'w') as f:
                    f.write(output_text)
                return output_text
            except ValueError:
                print("⚠️ 未能从 SSTImap 输出中提取注入点信息。")
                return results