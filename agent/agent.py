from openai import OpenAI
from rich import print
from datetime import datetime
import json, asyncio
from config import config
from .functions import function_map, all_tools
from typing import List, Dict, Any
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console
from openai.types import (
    Completion,
    FunctionDefinition,
    FunctionParameters
)

from .prompts import *
client = OpenAI(
    base_url=config.openai_base_url,
    api_key=config.openai_api_key,
)

async def function_call(progress: Progress, messages: list, tools: list) -> str:
    """
    Function call 调用工具并添加入消息列表。
    """
    task_id = progress.add_task("正在启动 Function call", total=100)
    while True:
        resp = client.chat.completions.create(
            model=config.openai_model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        msg = resp.choices[0].message
        messages.append(msg)
        if msg.tool_calls:
            tool_calls = msg.tool_calls
            tasks = []
            for tool_call in tool_calls:
                name = tool_call.function.name
                args = json.loads(tool_call.function.arguments)
                print(f"[grey54]  调用函数: {name}, 参数: {args}")
                progress.update(task_id, description=f"正在执行 {name}...")
                tasks.append(function_map[name](**args))

            results = await asyncio.gather(*tasks)
            
            for i, tool_call in enumerate(tool_calls):
                result = results[i]
                print(f"[green]🗸[/green] 函数 {tool_call.function.name} 执行完成")
                progress.update(task_id, description=f"函数 {tool_call.function.name} 完成")
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result, ensure_ascii=False)
                })
            continue
        break
    progress.update(task_id, completed=100)
    return msg.content or ""

async def url_injection_analysis(progress: Progress, url: str) -> str:
    """
    生成对指定 URL 注入端点的分析消息。
    """
    messages  = [{"role": "user", "content": url_injection_prompt.format(injection_url=url, time = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z"))}]
    # 从 all_tools 中提取只与  URL 注入扫描相关的工具
    url_tools = [tool for tool in all_tools if tool["function"]["name"] in [
        "scan_sql_injection", 
        "scan_template_injection",
        "fetch_url_content",
    ]]
    result = await function_call(progress, messages, tools=url_tools)
    return result

async def generate_domain_analysis(progress: Progress, domain: str) -> str:
    """
    生成对指定域名的分析消息。
    """
    messages  = [{"role": "user", "content": domain_scan_prompt.format(domain=domain, time = datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}]
    domain_tools = [tool for tool in all_tools if tool["function"]["name"] in [
        "scan_subdomain_enumeration",
        "scan_port_scanning",
    ]]
    result = await function_call(progress, messages, tools=domain_tools)
    return result

async def website_full_analysis(progress: Progress, website: str) -> str:
    """
    对整个网站进行全面扫描分析。
    """
    # TODO
    return ""

if __name__ == "__main__":
    async def test():
        """
        主函数，用于测试 URL 分析功能。
        """
        with Progress(
        SpinnerColumn(),
        TextColumn("[bold gray]{task.description}", justify="right"),
    ) as progress:
            url = "http://localhost:5000/?name=1"
            result = await url_injection_analysis(progress, url)
            print("URL 分析完成。")
            print(result)
    asyncio.run(test())