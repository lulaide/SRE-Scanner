import asyncio
from asyncio.subprocess import Process
from rich import print
from typing import Optional, Dict, List, Any
from httpx import AsyncClient
import json, os

class SqlmapExecutionError(Exception):
    """当 sqlmap 执行失败时抛出的自定义异常。"""
    def __init__(self, message, stderr):
        super().__init__(message)
        self.stderr = stderr

class Sqlmap:
    def __init__(self):
        self.sqlmap_api_path = 'tools/module_sqlmap/sqlmapapi.py'

    async def check(self) -> bool:
        process = await asyncio.create_subprocess_exec(
            "python", self.sqlmap_api_path, "--help",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        if process.returncode != 0:
            print(f"OneForAll 子模块 {self.sqlmap_api_path} 不可用。请检查路径。")
            return False
        return True

    async def start(self, host='127.0.0.1', port=8775):
        """启动 sqlmapapi.py 服务"""
        self.host = host
        self.port = port
        self.process: Optional[Process] = None
        self.cmd = [
            'python', self.sqlmap_api_path, '-s', '--host', self.host, '--port', str(self.port)
        ]
        print(f"正在启动 [green]sqlmap[/green] API 服务，地址: {self.host}:{self.port}...")
        print(f"执行命令: {' '.join(self.cmd)}")
        self.process = await asyncio.create_subprocess_exec(
            *self.cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        print("sqlmap API 已启动")
        return self.process

    async def stop(self):
        """停止 sqlmapapi.py 服务"""
        if self.process is None:
            print("sqlmap API 未运行。")
            return
        
        try:
            if self.process.returncode is None:
                self.process.terminate()
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=5)
                    print("[green]✔[/green] sqlmap API 已优雅停止。")
                except asyncio.TimeoutError:
                    print("超时，强制结束 sqlmap API 进程。")
                    self.process.kill()
                    await self.process.wait()
        except Exception as e:
            print(f"[yellow]停止进程时发生错误: {e}[/yellow]")
        finally:
            self.process = None

    async def restart(self):
        """重启 sqlmapapi.py 服务"""
        await self.stop()
        await self.start()
    async def scan(self, url: str, output_dir: str, data: Optional[str] = None, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """使用 httpx 异步调用 sqlmap API 执行扫描并获取结果"""
        api_url = f"http://{self.host}:{self.port}"
        headers = {'Content-Type': 'application/json'}
        task_id = None

        async with AsyncClient() as client:
            try:
                # 1. 创建新任务
                new_task_resp = await client.get(f"{api_url}/task/new")
                new_task_resp.raise_for_status()
                task_id = new_task_resp.json().get("taskid")
                if not task_id:
                    raise SqlmapExecutionError("创建 sqlmap 任务失败。", "未返回 taskid")

                print(f"已创建 sqlmap 任务: {task_id}")

                # 2. 设置扫描选项并启动扫描
                scan_options = options or {}
                scan_options['url'] = url
                if data:
                    scan_options['data'] = data

                start_scan_resp = await client.post(f"{api_url}/scan/{task_id}/start", json=scan_options, headers=headers)
                start_scan_resp.raise_for_status()
                if not start_scan_resp.json().get("success"):
                    raise SqlmapExecutionError(f"任务 {task_id} 启动扫描失败。", "API 返回 success: false")

                print(f"开始扫描 URL: {url}")

                # 3. 轮询扫描状态
                while True:
                    await asyncio.sleep(5)
                    status_resp = await client.get(f"{api_url}/scan/{task_id}/status")
                    status_resp.raise_for_status()
                    status_data = status_resp.json()
                    if status_data.get("status") == "terminated":
                        break
                    print(f"任务 {task_id} 正在扫描中...")

                # 4. 获取扫描结果
                data_resp = await client.get(f"{api_url}/scan/{task_id}/data")
                data_resp.raise_for_status()
                # 确保输出目录存在
                os.makedirs(output_dir, exist_ok=True)
                output_file_path = os.path.join(output_dir, "sqlmap_output.json")

                # 尝试读取已存在的结果
                existing_results = []
                if os.path.exists(output_file_path):
                    try:
                        with open(output_file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if content:  # 确保文件不为空
                                existing_results = json.loads(content)
                                if not isinstance(existing_results, list):
                                    print(f"[yellow]警告: {output_file_path} 的内容不是一个列表，将覆盖文件。[/yellow]")
                                    existing_results = []
                    except (json.JSONDecodeError, IOError) as e:
                        print(f"[yellow]读取或解析 {output_file_path} 时出错: {e}。将创建新文件。[/yellow]")
                        existing_results = []

                # 获取当前扫描的结果
                current_scan_results = data_resp.json().get("data", [])

                # 如果有新的发现，则添加到结果列表并写入文件
                if current_scan_results:
                    # 将新结果作为一个整体添加到现有结果列表
                    existing_results.append(current_scan_results)
                    
                    # 将更新后的列表写回文件
                    try:
                        with open(output_file_path, 'w', encoding='utf-8') as f:
                            json.dump(existing_results, f, indent=4, ensure_ascii=False)
                        print(f"[green]扫描结果已追加到 {output_file_path}[/green]")
                    except IOError as e:
                        print(f"[red]无法写入结果到 {output_file_path}: {e}[/red]")

                scan_results = data_resp.json().get("data", [])

                return scan_results

            except Exception as e:
                print(f"[red]sqlmap 扫描过程中发生错误: {e}[/red]")
                return []
            finally:
                # 5. 清理任务
                if task_id:
                    await client.get(f"{api_url}/scan/{task_id}/delete")
                    print(f"已清理 sqlmap 任务: {task_id}")
async def main():
    sqlmap_api = Sqlmap()  # 创建 sqlmap API 实例
    try:
        # 启动 sqlmap API
        await sqlmap_api.start()
        
        # 等待 API 服务启动完成
        await asyncio.sleep(3)
        print("[green]SQLMap API 已就绪[/green]")

        # 测试用例 1: GET 参数注入测试
        print("\n[cyan]正在测试 GET 参数注入...[/cyan]")
        get_url = "http://testphp.vulnweb.com/listproducts.php?cat=1"
        get_options = {
            "level": 1,
            "risk": 1,
            "batch": True,
            "technique": "B"  # Boolean-based blind
        }
        
        try:
            get_results = await asyncio.wait_for(
                sqlmap_api.scan(get_url, output_dir='test', options=get_options), 
                timeout=300  # 5分钟超时
            )
            if get_results:
                print(f"[green]GET 注入测试完成。发现 {len(get_results)} 个结果[/green]")
                for result in get_results:
                    print(f"  - {result}")
            else:
                print("[yellow]在 GET 参数中未发现漏洞[/yellow]")
        except asyncio.TimeoutError:
            print("[red]GET 参数注入测试超时（5分钟），跳过此测试[/red]")

        # 等待一下再进行下一个测试
        await asyncio.sleep(2)

        # 测试用例 2: POST 数据注入测试
        print("\n[cyan]正在测试 POST 数据注入...[/cyan]")
        post_url = "http://testphp.vulnweb.com/userinfo.php"
        post_data = "uname=admin&pass=password"
        post_options = {
            "level": 2,
            "risk": 2,
            "batch": True,
            "technique": "UE"  # Union query and Error-based
        }
        
        try:
            post_results = await asyncio.wait_for(
                sqlmap_api.scan(post_url, output_dir='test', data=post_data, options=post_options),
                timeout=300  # 5分钟超时
            )
            if post_results:
                print(f"[green]POST 注入测试完成。发现 {len(post_results)} 个结果[/green]")
                for result in post_results:
                    print(f"  - {result}")
            else:
                print("[yellow]在 POST 数据中未发现漏洞[/yellow]")
        except asyncio.TimeoutError:
            print("[red]POST 数据注入测试超时（5分钟），跳过此测试[/red]")

        # 等待一下再进行下一个测试
        await asyncio.sleep(2)

        # 测试用例 3: Cookie 注入测试
        print("\n[cyan]正在测试 Cookie 注入...[/cyan]")
        cookie_url = "http://testphp.vulnweb.com/secured/newuser.php"
        cookie_options = {
            "cookie": "PHPSESSID=test123; security=low",
            "level": 3,
            "risk": 1,
            "batch": True,
            "testParameter": "PHPSESSID"
        }
        
        try:
            cookie_results = await asyncio.wait_for(
                sqlmap_api.scan(cookie_url, output_dir='test', options=cookie_options),
                timeout=20
            )
            if cookie_results:
                print(f"[green]Cookie 注入测试完成。发现 {len(cookie_results)} 个结果[/green]")
                for result in cookie_results:
                    print(f"  - {result}")
            else:
                print("[yellow]在 Cookie 中未发现漏洞[/yellow]")
        except asyncio.TimeoutError:
            print("[red]Cookie 注入测试超时，跳过此测试[/red]")

        # 测试用例 4: 错误处理测试
        print("\n[cyan]正在测试无效 URL 的错误处理...[/cyan]")
        try:
            invalid_results = await asyncio.wait_for(
                sqlmap_api.scan("invalid-url", output_dir='test', options={"batch": True}),
                timeout=300  # 5分钟超时
            )
            print(f"无效 URL 测试结果: {invalid_results}")
        except asyncio.TimeoutError:
            print("[red]错误处理测试超时（5分钟），跳过此测试[/red]")
        except Exception as e:
            print(f"[red]预期错误已捕获: {e}[/red]")

        print("\n[green]所有测试已成功完成！[/green]")

    except SqlmapExecutionError as e:
        print(f"[red]SQLMap 执行错误: {e}[/red]")
        print(f"[red]错误详情: {e.stderr}[/red]")
    except Exception as e:
        print(f"[red]意外错误: {e}[/red]")
    finally:
        # 确保 API 服务被停止
        print("\n[yellow]正在停止 SQLMap API...[/yellow]")
        await sqlmap_api.stop()
        print("[green]测试会话已结束[/green]")

# 执行主程序
if __name__ == "__main__":
    asyncio.run(main())