import asyncio
import questionary
from asyncio.subprocess import Process
from rich import print
import subprocess
from tools import *

# 定义需要检测的工具列表
TOOLS_TO_CHECK = [
    "nmap",
    "hydra",
    "dirb",
    "ffuf",
    "msfconsole"
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

def install_tool(tool_name: str) -> None:
    """
    安装工具

    Args:
        tool_name: 要安装的工具名称。
    """

    print(f"🔧 正在安装 {tool_name}...")
    try:
        # 使用 apt-get 安装工具。-y 选项会自动回答 "yes"
        # 注意: 这需要用户有 sudo 权限，并且可能在执行时提示输入密码。
        process = subprocess.run(
            ["sudo", "apt-get", "install", "-y", tool_name],
            capture_output=True,
            text=True,
            check=False  # 设置为 False，手动检查返回码
        )
        
        if process.returncode != 0:
            # 如果安装失败，打印错误信息
            print(f"[red]🗴[/red] 安装 {tool_name} 失败。")
            error_message = process.stderr.strip()
            if error_message:
                print(f"[red]🗴[/red] 错误详情: {error_message}")
            return  # 安装失败，提前返回

    except FileNotFoundError:
        print("[red]🗴[/red] 命令 'sudo' 或 'apt-get' 未找到。请确保您在基于 Debian/Ubuntu 的系统上运行，并已安装 sudo。")
        return
    except Exception as e:
        print(f"安装 '{tool_name}' 时发生意外错误: {e}")
        return
    print(f"[green]🗸[/green] {tool_name} 安装完成！")

async def check_wrappers():
    """
    检查所有工具的 wrapper 是否可用。
    """
    tasks = [
        sstimap_wrapper.SSTImap().check(),
        oneforall_wrapper.OneForAll().check(),
        sqlmap_wrapper.Sqlmap().check()
    ]
    results = await asyncio.gather(*tasks)
    
    for result in results:
        if not result:
            print("[red]🗴[/red] 某些工具的 wrapper 不可用，请检查路径或安装状态。")
            return False
    print("[green]🗸[/green] 所有工具的 wrapper 均可用。")
    return True

async def checker():
    """
    主函数，协调整个检测流程。
    """
    tasks = [check_tool_availability(tool) for tool in TOOLS_TO_CHECK]
    results = await asyncio.gather(*tasks)
    
    # 分类并展示结果
    found_tools = []
    not_found_tools = []
    
    for tool, path in results:
        if path:
            found_tools.append((tool, path))
        else:
            not_found_tools.append(tool)
            
    # 打印找到的工具
    if found_tools:
        print("[green]🗸[/green] 找到以下工具:")
        for tool, path in found_tools:
            print(f"  - {tool:<25} -> 路径: {path}")

    # 打印未找到的工具
    if not_found_tools:
        print("\n[red]🗴[/red] 未找到以下工具:")
        for tool in not_found_tools:
            print(f"  - {tool}")
        # print("\n💡 提示: 请确保这些工具已正确安装并已将其路径添加到系统的 PATH 环境变量中。")

        should_install = await questionary.confirm(
            "是否需要安装未找到的工具?",
            default=True,
            auto_enter=False
        ).ask_async()
        if should_install:
            print("\n🔧 正在安装未找到的工具...")
            for tool in not_found_tools:
                install_tool(tool)
            print("\n🔧 安装完成!")

    # 检查工具的 wrapper 是否可用
    print("  正在检查工具的 wrapper 是否可用...")
    await check_wrappers()