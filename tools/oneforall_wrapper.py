import asyncio
import json
from rich import print
from typing import Optional, Dict, List, Any

class OneForAllExecutionError(Exception):
    """当 OneForAll 执行失败时抛出的自定义异常。"""
    def __init__(self, message, stderr):
        super().__init__(message)
        self.stderr = stderr

class OneForAll:
    def __init__(self):
        self.oneforall_path = "tools/module_oneforall/oneforall.py"
    async def check(self) -> bool:
        process = await asyncio.create_subprocess_exec(
            "python", self.oneforall_path, "--help",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        if process.returncode != 0:
            print(f"OneForAll 子模块 {self.oneforall_path} 不可用。请检查路径。")
            return False
        return True

    async def scan(
        self,
        domain: str,
        output_dir: str,
        extra_args: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        异步执行 OneForAll 扫描。

        Args:
            domain (str): 目标域名。
            output_dir (str): 输出目录。
            extra_args (Optional[List[str]]): 其他要传递给 OneForAll 的原始参数。

        Returns:
            List[Dict[str, Any]]: OneForAll 扫描结果的列表，每个结果是一个字典。

        Raises:
            OneForAllExecutionError: 如果 OneForAll 执行失败或返回非零退出码。
        """
        file_path = f"{output_dir}/oneforall_output.json"
        
        # 构建命令列表
        cmd = [
            "python",
            "tools/module_oneforall/oneforall.py",
            "--fmt=json",
            f"--path={file_path}",
            "--target", domain,
            "run"
        ]
        if extra_args:
            cmd.extend(extra_args)

        # 执行命令
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise OneForAllExecutionError(
                f"OneForAll 执行失败，返回码：{process.returncode}",
                stderr.decode()
            )

        # 解析输出文件
        with open(file_path, 'r') as f:
            results = json.load(f)

        return results
            