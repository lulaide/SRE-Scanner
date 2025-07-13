import asyncio
import questionary
import sys
from asyncio.subprocess import Process
from rich import print
import click
from tools import *
from tools_check import checker

@click.command()
@click.argument('host')
@click.option(
    '--no-check',
    '-n',
    is_flag=True,
    help='跳过工具检查'
    )
def host_scan(host, no_check):
    if not no_check:
        asyncio.run(checker())
    print(f"Scanning host: {host}")

if __name__ == '__main__':
    host_scan()
