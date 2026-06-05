#!/usr/bin/env python3
"""
AI代码安全审计工具 - aiguard
用法: aiguard <文件路径> [选项]
"""
import sys
import argparse
import json
from pathlib import Path
from openai import OpenAI
import os
from dotenv import load_dotenv

# 加载 .env 文件中的环境变量
load_dotenv()

# 配置AI客户端
client = OpenAI(
    api_key=os.getenv("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com/v1"
)

# 统一的提示词（强制输出 CWE 编号）
SYSTEM_PROMPT = """你是 Python 代码安全审计专家，拥有 10 年安全经验。请仔细分析代码，**找出所有安全漏洞**。

输出格式严格遵循以下模板（每条漏洞必须包含：严重程度、问题描述、行号、修复建议、CWE编号）：

[高危] 问题描述 - 第X行
  CWE: CWE-xxx（漏洞类型编号）
  问题: 详细说明为什么这是个安全问题
  修复建议: 提供具体的代码修改方案，展示"错误写法→正确写法"

[中危] 问题描述 - 第X行
  CWE: CWE-xxx
  问题: 详细说明
  修复建议: 具体方案

[低危] 问题描述 - 第X行
  CWE: CWE-xxx
  问题: 详细说明
  修复建议: 具体方案

**每个漏洞必须包含 CWE 编号，格式如：CWE-89（SQL注入）**

**规则：**
1. 如果代码有多个漏洞，全部列出，不要遗漏，不要合并。
2. 修复建议必须可直接复制粘贴使用。
3. CWE 编号必须与漏洞类型对应，参考：
   - SQL注入: CWE-89
   - 命令注入: CWE-78
   - 硬编码密码: CWE-798
   - eval执行: CWE-95
   - pickle反序列化: CWE-502
   - 路径遍历: CWE-22
4. 如果没有漏洞，输出：✅ 未发现明显安全漏洞

请开始审计："""


def parse_ai_result(result_text):
    """解析 AI 输出的漏洞报告，提取结构化数据"""
    issues = []
    lines = result_text.strip().split('\n')
    current_issue = {}

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith('[高危]') or line.startswith('[中危]') or line.startswith('[低危]'):
            if current_issue:
                issues.append(current_issue)

            parts = line.split(']', 1)
            severity = parts[0][1:]
            description = parts[1].strip() if len(parts) > 1 else ''

            current_issue = {
                "severity": severity,
                "description": description,
                "cwe": "",
                "problem": "",
                "suggestion": ""
            }
        elif line.startswith('CWE:'):
            current_issue["cwe"] = line.replace('CWE:', '').strip()
        elif line.startswith('问题:'):
            current_issue["problem"] = line.replace('问题:', '').strip()
        elif line.startswith('修复建议:'):
            current_issue["suggestion"] = line.replace('修复建议:', '').strip()

    if current_issue:
        issues.append(current_issue)

    return issues


def generate_html_report(issues, filepath):
    """生成 HTML 格式的报告"""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>代码审计报告 - {filepath}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
        .critical {{ color: #d32f2f; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .issue {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }}
        .cwe {{ font-family: monospace; color: #666; }}
        pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>🔍 代码审计报告</h1>
    <div class="summary">
        <strong>文件:</strong> {filepath}<br>
        <strong>扫描时间:</strong> {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        <strong>漏洞总数:</strong> {len(issues)}
    </div>
"""
    for issue in issues:
        severity_class = {
            "高危": "critical",
            "中危": "medium",
            "低危": "low"
        }.get(issue.get("severity", ""), "")

        html += f"""
    <div class="issue">
        <h3 class="{severity_class}">[{issue.get('severity', '未知')}] {issue.get('description', '')}</h3>
        <p><strong>CWE:</strong> <span class="cwe">{issue.get('cwe', 'N/A')}</span></p>
        <p><strong>问题描述:</strong> {issue.get('problem', '')}</p>
        <p><strong>修复建议:</strong></p>
        <pre>{issue.get('suggestion', '')}</pre>
    </div>
"""
    html += """
</body>
</html>"""
    return html


def scan_file(filepath, quiet=False):
    """扫描单个Python文件"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
    except Exception as e:
        if not quiet:
            print(f"❌ 读取文件失败: {e}")
        return None, None

    if not quiet:
        print(f"\n🔍 正在审计: {filepath}")
        print("=" * 60)

    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"审计这段Python代码:\n```python\n{code}\n```"}
            ],
            temperature=0.3,
        )

        result = response.choices[0].message.content
        if not quiet:
            print(result)
            print("\n" + "=" * 60)

        # 解析结果
        issues = parse_ai_result(result) if "✅" not in result else []
        return result, issues

    except Exception as e:
        if not quiet:
            print(f"❌ AI分析失败: {e}")
            print("提示: 请检查API Key是否正确，或网络是否畅通")
        return None, None


def scan_directory(dirpath, quiet=False):
    """扫描目录下所有Python文件"""
    dir_path = Path(dirpath)
    if not dir_path.is_dir():
        if not quiet:
            print(f"❌ 不是有效目录: {dirpath}")
        return []

    py_files = list(dir_path.rglob("*.py"))
    if not py_files:
        if not quiet:
            print(f"⚠️ 目录下没有找到Python文件: {dirpath}")
        return []

    if not quiet:
        print(f"\n🔍 找到 {len(py_files)} 个Python文件，开始扫描...")
        print("=" * 60)

    results = []
    for i, py_file in enumerate(py_files, 1):
        if not quiet:
            print(f"\n[{i}/{len(py_files)}] 正在审计: {py_file}")

        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                code = f.read()

            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"审计这段Python代码:\n```python\n{code}\n```"}
                ],
                temperature=0.3,
            )
            result = response.choices[0].message.content
            if not quiet:
                print(result)

            if "✅" not in result:
                issues = parse_ai_result(result)
                results.append({
                    "file": str(py_file),
                    "issues": issues
                })
        except Exception as e:
            if not quiet:
                print(f"❌ 审计失败: {e}")

    if not quiet:
        print("\n" + "=" * 60)
        print(f"\n📊 扫描完成！共发现 {len(results)} 个文件存在问题")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="AI代码安全审计工具",
        epilog="示例: aiguard app.py\n       aiguard ./src\n       aiguard app.py --output report.json\n       aiguard ./src --format html --output report.html"
    )
    parser.add_argument("target", help="要扫描的Python文件或目录路径")
    parser.add_argument("--output", "-o", help="输出报告文件路径（支持 .json 或 .html）")
    parser.add_argument("--format", "-f", choices=["json", "html"], help="输出格式（与 --output 配合使用）")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式，只输出最终结果")
    parser.add_argument("--version", action="version", version="aiguard 0.5.0")
    args = parser.parse_args()

    target_path = Path(args.target)

    # 如果指定了 --output 但没有指定 --format，根据文件扩展名自动判断
    output_format = args.format
    if args.output and not output_format:
        if args.output.endswith('.json'):
            output_format = 'json'
        elif args.output.endswith('.html'):
            output_format = 'html'

    result_data = None
    raw_result = None

    if target_path.is_file():
        raw_result, issues = scan_file(str(target_path), quiet=args.quiet)
        if issues:
            result_data = issues
    elif target_path.is_dir():
        result_data = scan_directory(str(target_path), quiet=args.quiet)
    else:
        if not args.quiet:
            print(f"❌ 文件或目录不存在: {args.target}")
        sys.exit(1)

    # 输出报告文件
    if args.output and result_data:
        try:
            if output_format == 'json':
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(result_data, f, ensure_ascii=False, indent=2)
            elif output_format == 'html' and target_path.is_file() and raw_result:
                # 单文件 HTML 报告
                html_content = generate_html_report(result_data, str(target_path))
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            elif output_format == 'html' and target_path.is_dir():
                # 目录扫描的 HTML 报告
                html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>代码审计报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f0f0f0; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>🔍 代码审计报告</h1>
    <div class="summary">
        <strong>扫描目录:</strong> {target_path}<br>
        <strong>扫描时间:</strong> {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        <strong>发现问题文件数:</strong> {len(result_data)}
    </div>
    <h2>问题文件列表</h2>
    <ul>
"""
                for item in result_data:
                    html_content += f"        <li><strong>{item['file']}</strong> - 发现 {len(item.get('issues', []))} 个漏洞</li>\n"
                html_content += """    </ul>
</body>
</html>"""
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(html_content)

            if not args.quiet:
                print(f"\n📄 报告已保存到: {args.output}")
        except Exception as e:
            if not args.quiet:
                print(f"❌ 保存报告失败: {e}")


if __name__ == "__main__":
    main()