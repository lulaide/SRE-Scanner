import asyncio
import questionary
import sys
from asyncio.subprocess import Process
from rich import print
import click
from tools import *
from tools_check import checker
from agent import *

from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console

console = Console()

@click.command()
@click.argument('website', type=str, default=None, required=False)
@click.option(
    '--no-check',
    '-n',
    is_flag=True,
    help='跳过工具检查'
    )
@click.option(
    '-u',
    '--url',
    required=False,
    help='指定 URL端点 进行注入分析, 例如: http://example.com/?name=1',
)
@click.option(
    '-h',
    '--host',
    required=False,
    help='指定主机进行扫描, 例如: example.com',
)
def main(website, no_check, url, host):
    'main.py https://example.com/ 对一个网站进行完整扫描'
    result = None
    
    if not website and not url and not host:
        if questionary.confirm(
            "是否进行工具检查？",
        ).ask():
            asyncio.run(checker())
        scan_type = questionary.select(
        "请选择要进行的扫描类型：",
        choices=[
            "网站扫描",
            "URL注入分析",
            "主机扫描",
        ]
        ).ask()

        if scan_type == "网站扫描":
            website = questionary.text("请输入网站地址 (例如: https://example.com):").ask()
            # 如果提前启动 Process 会导致 Questionary 无法正常工作
            with Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
                ) as progress:
                result = asyncio.run(website_full_analysis(progress, website))
                print(f"[green]🗸[/green] 网站自动扫描完成。")
        elif scan_type == "URL注入分析":
            url = questionary.text("请输入 URL 端点 (例如: http://example.com/?name=1):").ask()
            with Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
            ) as progress:
                result = asyncio.run(url_injection_analysis(progress, url))
                print(f"[green]🗸[/green] 注入分析完成。")
        elif scan_type == "主机扫描":
            host = questionary.text("请输入主机地址 (例如: example.com):").ask()
            with Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
            ) as progress:
                result = asyncio.run(generate_domain_analysis(progress, host))
                print(f"[green]🗸[/green] 主机 {host} 扫描完成。")


    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
        ) as progress:
            if website:
                if not no_check:
                    asyncio.run(checker())
                result = asyncio.run(website_full_analysis(progress, website))
                print(f"[green]🗸[/green] 网站自动扫描完成。")
            elif url:
                if not no_check:
                    asyncio.run(checker())
                result = asyncio.run(url_injection_analysis(progress, url))
                print(f"[green]🗸[/green] 注入分析完成。")
            elif host:
                if not no_check:
                    asyncio.run(checker())
                result = asyncio.run(generate_domain_analysis(progress, host))
                print(f"[green]🗸[/green] 主机 {host} 扫描完成。")

    if result:
        print(result)
if __name__ == '__main__':
    main()
