from openai import OpenAI
from rich import print
import json, asyncio
from config import config
from .functions import function_map, all_tools
from typing import List, Dict, Any
from rich.markdown import Markdown
from openai.types import (
    Completion,
    FunctionDefinition,
    FunctionParameters
)

from .prompts import (
    url_analysis_prompt
)
client = OpenAI(
    base_url=config.openai_base_url,
    api_key=config.openai_api_key,
)

async def function_call(messages: list, tools: list) -> str:
    """
    Function call 调用工具并添加入消息列表。
    """
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
                print(f"准备异步调用函数: {name}, 参数: {args}")
                tasks.append(function_map[name](**args))

            results = await asyncio.gather(*tasks)
            
            for i, tool_call in enumerate(tool_calls):
                result = results[i]
                print(f"函数 {tool_call.function.name} 异步执行结果: \n{result}")
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result, ensure_ascii=False)
                })
            continue
        break
    return msg.content or ""

async def generate_url_analysis(url: str) -> str:
    """
    生成对指定 URL 的分析消息。
    """
    messages  = [{"role": "user", "content": url_analysis_prompt.format(url=url)}]
    # 从 all_tools 中提取只与 web URL 扫描相关的工具
    url_tools = [tool for tool in all_tools if tool["function"]["name"] in [
        "scan_directory_fuzzing",
        "scan_sql_injection", 
        "scan_template_injection"
    ]]
    result = await function_call(messages, tools=url_tools)
    return result

if __name__ == "__main__":
    async def main():
        """
        主函数，用于测试 URL 分析功能。
        """
        url = "http://192.168.100.175:8080/"
        result = await generate_url_analysis(url)
        print("URL 分析完成。")
        print(Markdown(result))
        print(result)
    asyncio.run(main())