#!/usr/bin/env python3
"""
Kali 工具检测器

本脚本使用 asyncio 和 questionary 异步检测一系列渗透测试工具
是否在系统的 PATH 中可用。

功能:
- 异步并发检测，速度快。
- 使用 `which` 命令检查工具是否存在。
- 通过 questionary 提供交互式用户体验。
- 清晰地展示检测结果。
"""

import asyncio
import questionary
import sys
from asyncio.subprocess import Process

# 定义需要检测的工具列表
TOOLS_TO_CHECK = [
    "nmap",
    "sqlmap",
    "hydra",
    "ffuf",
    "metasploit-framework", # Metasploit
    "john",               # John the Ripper
    "hashcat",
    "burpsuite",
    "wireshark",
    "aircrack-ng",
]

async def check_tool_availability(tool_name: str) -> tuple[str, str | None]:
    """
    异步检查单个工具是否在 PATH 中可用。

    Args:
        tool_name: 要检查的工具名称。

    Returns:
        一个元组，包含工具名称和它的路径 (如果找到)，否则为 None。
    """
    try:
        # 在 Unix/Linux/macOS 上使用 'which'
        command = "which"
        
        process: Process = await asyncio.create_subprocess_exec(
            command,
            tool_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            # 解码并去除路径末尾的换行符
            path = stdout.decode().strip()
            return tool_name, path
        else:
            return tool_name, None
            
    except FileNotFoundError:
        # 如果 'which' 命令本身不存在
        return tool_name, None
    except Exception as e:
        print(f"检查 '{tool_name}' 时发生意外错误: {e}")
        return tool_name, None

async def main():
    """
    主函数，协调整个检测流程。
    """

    # 1. 询问用户是否开始扫描
    should_start = await questionary.confirm(
        "是否开始扫描系统中的渗透测试工具?",
        default=True,
        auto_enter=False  # auto_enter=False 确保在异步环境中正常工作
    ).ask_async()
    
    if not should_start:
        print("👋 操作已取消，再见!")
        sys.exit(0)
        
    # 2. 并发执行所有工具的检测
    print("\n🚀 正在异步检测工具，请稍候...")
    
    tasks = [check_tool_availability(tool) for tool in TOOLS_TO_CHECK]
    results = await asyncio.gather(*tasks)
    
    # 3. 分类并展示结果
    found_tools = []
    not_found_tools = []
    
    for tool, path in results:
        if path:
            found_tools.append((tool, path))
        else:
            not_found_tools.append(tool)
            
    print("\n📊 检测结果:")
    
    # 打印找到的工具
    if found_tools:
        print("✅ 找到以下工具:")
        for tool, path in found_tools:
            print(f"  - {tool:<25} -> 路径: {path}")
    else:
        print("✅ 没有在 PATH 中找到任何指定的工具。")
        
    # 打印未找到的工具
    if not_found_tools:
        print("\n❌ 未找到以下工具:")
        for tool in not_found_tools:
            print(f"  - {tool}")
        print("\n💡 提示: 请确保这些工具已正确安装并已将其路径添加到系统的 PATH 环境变量中。")
        
    print("\n🎉 检测完成!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        print("\n👋 用户中断了程序，再见!")
        sys.exit(0)
