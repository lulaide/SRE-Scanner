import asyncio
import json
import os
import re
from rich import print
from typing import Optional, Dict, List, Any

class WebTreeExecutionError(Exception):
    """当 WebTree 执行失败时抛出的自定义异常。"""
    def __init__(self, message, stderr):
        super().__init__(message)
        self.stderr = stderr

def clean_ansi_codes(text: str) -> str:
    """
    清理文本中的ANSI颜色代码和控制字符
    """
    # 移除ANSI转义序列
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', text)
    
    # 移除常见的颜色代码格式如 [32m, [0m 等
    color_code_pattern = re.compile(r'\[[0-9;]*m')
    cleaned = color_code_pattern.sub('', cleaned)
    
    return cleaned

class WebTree:
    def __init__(self):
        self.webtree_path = "tools/module_WebTree"
    
    async def check(self) -> bool:
        """检查 WebTree 工具是否可用"""
        try:
            # 检查 node 是否安装
            process = await asyncio.create_subprocess_exec(
                "node", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.webtree_path
            )
            await process.communicate()
            if process.returncode != 0:
                print(f"Node.js 不可用，请确保已安装 Node.js")
                return False
            
            # 检查 index.js 文件是否存在
            index_js_path = os.path.join(self.webtree_path, "index.js")
            if not os.path.exists(index_js_path):
                print(f"WebTree 工具文件 {index_js_path} 不存在")
                return False
            
            return True
        except Exception as e:
            print(f"检查 WebTree 工具时出错: {e}")
            return False

    async def scan(
        self,
        target_url: str,
        use_poc: bool = False,
        use_detail: bool = False,
        concurrency: int = 10,
        max_links: int = 100,
        output_file: Optional[str] = None,
        timeout: int = 300
    ) -> Optional[str]:
        """
        使用 WebTree 扫描网站
        
        Args:
            target_url: 目标网站URL
            use_poc: 是否使用POC检测
            use_detail: 是否输出详细的POC执行结果（需要use_poc=True）
            concurrency: 并发请求数
            max_links: 最大访问链接数量限制
            output_file: 输出文件路径（可选）
            timeout: 超时时间（秒）
            
        Returns:
            扫描结果字符串，如果失败则返回 None
        """
        try:
            # 构建命令参数
            cmd_args = ["node", "index.js", target_url]
            
            # 添加选项
            if concurrency != 10:
                cmd_args.extend(["-c", str(concurrency)])
            
            if max_links != 100:
                cmd_args.extend(["-m", str(max_links)])
            
            if use_poc:
                cmd_args.append("--poc")
                if use_detail:
                    cmd_args.append("--detail")
            
            if output_file:
                cmd_args.extend(["-o", output_file])
            
            print(f"[blue]🔍[/blue] 正在使用 WebTree 扫描: {target_url}")
            if use_poc:
                print(f"[blue]🔬[/blue] 已启用POC检测")
            
            # 执行 WebTree 扫描
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.webtree_path
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise WebTreeExecutionError(
                    f"WebTree 扫描超时 ({timeout}秒)", 
                    "执行超时"
                )
            
            if process.returncode != 0:
                error_msg = f"WebTree 执行失败，返回代码: {process.returncode}"
                if stderr:
                    error_msg += f"\n错误信息: {stderr.decode('utf-8', errors='ignore')}"
                raise WebTreeExecutionError(error_msg, stderr.decode('utf-8', errors='ignore'))
            
            # 解析输出
            output = stdout.decode('utf-8', errors='ignore')
            if not output.strip():
                print(f"[yellow]⚠️[/yellow] WebTree 扫描完成，但没有输出结果")
                return None
            
            print(f"[green]✅[/green] WebTree 扫描完成")
            
            # 清理ANSI颜色代码
            cleaned_output = clean_ansi_codes(output)
            
            # 如果指定了输出文件，也读取文件内容
            if output_file and os.path.exists(os.path.join(self.webtree_path, output_file)):
                try:
                    with open(os.path.join(self.webtree_path, output_file), 'r', encoding='utf-8') as f:
                        file_content = f.read()
                    cleaned_file_content = clean_ansi_codes(file_content)
                    return f"控制台输出:\n{cleaned_output}\n\n文件输出:\n{cleaned_file_content}"
                except Exception as e:
                    print(f"[yellow]⚠️[/yellow] 读取输出文件失败: {e}")
                    return cleaned_output
            
            return cleaned_output
            
        except WebTreeExecutionError:
            raise
        except Exception as e:
            raise WebTreeExecutionError(f"执行 WebTree 时发生意外错误: {str(e)}", str(e))

    async def scan_with_options(
        self,
        target_url: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        使用自定义选项扫描网站
        
        Args:
            target_url: 目标网站URL
            options: 扫描选项字典，支持的选项：
                - poc: 是否使用POC检测 (默认: False)
                - detail: 是否输出详细的POC执行结果 (默认: False)
                - concurrency: 并发请求数 (默认: 10)
                - max_links: 最大访问链接数量限制 (默认: 100)
                - output_file: 输出文件路径 (可选)
                - timeout: 超时时间 (默认: 300)
            
        Returns:
            扫描结果字符串
        """
        if options is None:
            options = {}
        
        use_poc = options.get('poc', False)
        use_detail = options.get('detail', False)
        concurrency = options.get('concurrency', 10)
        max_links = options.get('max_links', 100)
        output_file = options.get('output_file')
        timeout = options.get('timeout', 300)
        
        return await self.scan(
            target_url, 
            use_poc=use_poc, 
            use_detail=use_detail,
            concurrency=concurrency,
            max_links=max_links,
            output_file=output_file,
            timeout=timeout
        )

# 创建全局实例
webtree = WebTree()
