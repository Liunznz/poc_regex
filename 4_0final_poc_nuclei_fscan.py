import os
import re
import pandas as pd
from glob import glob

# ---------- 漏洞类型映射表 ----------
VULN_MAPPING = {
    # ==================== 注入类 ====================
    "sql injection": "SQL注入",
    "sqli": "SQL注入",
    "blind sql injection": "盲注SQL注入",
    "time based blind sql injection": "时间盲注SQL注入",
    "boolean based blind sql injection": "布尔盲注SQL注入",
    "code injection": "代码注入",
    "command injection": "命令注入",
    "php object injection": "PHP对象注入",
    "object injection": "对象注入",
    "expression language injection": "表达式语言注入",
    "el injection": "表达式语言注入",
    "ldap injection": "LDAP注入",
    "nosql injection": "NoSQL注入",
    "orm injection": "ORM注入",
    "xpath injection": "XPath注入",
    "host header injection": "Host头注入",
    "crlf injection": "CRLF注入",
    "log injection": "日志注入",
    "http parameter pollution": "HTTP参数污染",               # 新增
    "parameter pollution": "参数污染",                         # 新增
    "format string vulnerability": "格式化字符串漏洞",         # 已存在但格式不统一，保留此标准化条目
    "format string error": "格式化字符串错误",                 # 新增
    "insecure cookie handling": "Cookie验证错误",             # 新增
    "shell injection": "Shell注入",                           # 新增
    "xpath injection": "XPath注入",                           # 已存在，重复条目，已做去重

    # ==================== 跨站脚本 ====================
    "cross site scripting": "跨站脚本",
    "xss": "跨站脚本",
    "stored cross site scripting": "存储型跨站脚本",
    "reflected cross site scripting": "反射型跨站脚本",
    "dom based cross site scripting": "DOM型跨站脚本",
    "universal cross site scripting": "通用型跨站脚本",
    "self cross site scripting": "自跨站脚本",

    # ==================== 请求伪造 ====================
    "cross site request forgery": "跨站请求伪造",
    "csrf": "跨站请求伪造",
    "server side request forgery": "服务端请求伪造",
    "ssrf": "服务端请求伪造",
    "cross site websocket hijacking": "跨站WebSocket劫持",

    # ==================== 文件相关 ====================
    "arbitrary file upload": "任意文件上传",
    "file upload": "文件上传",
    "unrestricted file upload": "无限制文件上传",
    "local file inclusion": "本地文件包含",
    "lfi": "本地文件包含",
    "remote file inclusion": "远程文件包含",
    "rfi": "远程文件包含",
    "path traversal": "路径遍历",
    "directory traversal": "目录遍历",
    "arbitrary file download": "任意文件下载",
    "arbitrary file read": "任意文件读取",
    "file disclosure": "文件泄露",
    "file inclusion": "文件包含",
    "arbitrary file creation": "任意文件创建",               # 新增
    "arbitrary file deletion": "任意文件删除",               # 新增

    # ==================== 权限与授权 ====================
    "missing authorization": "缺失授权",
    "authorization bypass": "授权绕过",
    "privilege escalation": "权限提升",
    "authentication bypass": "认证绕过",
    "broken access control": "访问控制破坏",
    "insecure direct object reference": "不安全的直接对象引用",
    "idor": "不安全的直接对象引用",
    "session fixation": "会话固定",
    "session hijacking": "会话劫持",

    # ==================== 信息泄露 ====================
    "information disclosure": "信息泄露",
    "information exposure": "信息暴露",
    "sensitive data exposure": "敏感数据暴露",
    "source code disclosure": "源码泄露",
    "full path disclosure": "完整路径泄露",
    "debug information disclosure": "调试信息泄露",

    # ==================== 远程代码执行 ====================
    "remote code execution": "远程代码执行",
    "rce": "远程代码执行",
    "arbitrary code execution": "任意代码执行",
    "remote command execution": "远程命令执行",
    "command execution": "命令执行",                         # 新增

    # ==================== 模板注入 ====================
    "server side template injection": "服务端模板注入",
    "ssti": "服务端模板注入",
    "client side template injection": "客户端模板注入",
    "csti": "客户端模板注入",

    # ==================== 反序列化 ====================
    "insecure deserialization": "不安全反序列化",
    "deserialization of untrusted data": "不可信数据反序列化",
    "java deserialization": "Java反序列化",
    "php deserialization": "PHP反序列化",
    "python deserialization": "Python反序列化",

    # ==================== XML相关 ====================
    "xml external entity": "XML外部实体注入",
    "xxe": "XML外部实体注入",
    "xslt injection": "XSLT注入",
    "xml injection": "XML注入",

    # ==================== 其他Web常见漏洞 ====================
    "open redirect": "开放重定向",
    "denial of service": "拒绝服务",
    "dos": "拒绝服务",
    "ddos": "分布式拒绝服务",                                 # 新增
    "distributed denial of service": "分布式拒绝服务",       # 新增
    "captcha bypass": "验证码绕过",
    "clickjacking": "点击劫持",
    "content spoofing": "内容欺骗",
    "cache poisoning": "缓存投毒",
    "http request smuggling": "HTTP请求走私",
    "http response splitting": "HTTP响应拆分",
    "host header injection": "Host头注入",
    "race condition": "竞争条件",
    "weak password policy": "弱密码策略",
    "brute force": "暴力破解",
    "credential stuffing": "凭证填充",
    "subdomain takeover": "子域名接管",
    "dns spoofing": "DNS欺骗",
    "email spoofing": "邮件欺骗",
    "web cache deception": "Web缓存欺骗",
    "graphql introspection": "GraphQL内省泄露",
    "jwt weakness": "JWT弱点",
    "oauth misconfiguration": "OAuth配置错误",
    "variable coverage": "变量覆盖",                         # 新增
    "weak randomness": "弱随机性",                            # 已存在
    "insufficient logging & monitoring": "日志与监控不足",

    # ==================== 内存/二进制漏洞 ====================
    "buffer overflow": "缓冲区溢出",
    "stack overflow": "栈溢出",
    "heap overflow": "堆溢出",
    "integer overflow": "整数溢出",
    "use after free": "释放后使用",
    "double free": "双重释放",
    "null pointer dereference": "空指针解引用",
    "type confusion": "类型混淆",
    "out of bounds write": "越界写入",                       # 新增
    "out of bounds read": "越界读取",                         # 新增

    # ==================== 特定软件/框架/库漏洞 ====================
    "log4shell": "Log4j2远程代码执行漏洞",
    "log4j jndi injection": "Log4j2 JNDI注入漏洞",
    "spring4shell": "Spring框架远程代码执行漏洞",
    "shiro rememberme rce": "Shiro默认密钥致命令执行漏洞",
    "fastjson rce": "Fastjson反序列化漏洞",
    "heartbleed": "心脏出血漏洞",
    "shellshock": "破壳漏洞",
    "eternalblue": "永恒之蓝漏洞",
    "bluekeep": "BlueKeep远程桌面漏洞",
    "dirty pipe": "脏管道漏洞",
    "dirty cow": "脏牛漏洞",
    "pwnkit": "Polkit权限提升漏洞",
    "proxylogon": "ProxyLogon漏洞",
    "proxyshell": "ProxyShell漏洞",
    "petitpotam": "PetitPotam NTLM中继攻击",

    # ==================== 其他补充 ====================
    "business logic flaw": "业务逻辑缺陷",
    "business logic vulnerability": "业务逻辑漏洞",
    "race condition": "竞争条件",                             # 已存在
    "weak randomness": "弱随机性",
    "insecure cryptographic storage": "不安全加密存储",
    "missing encryption": "缺少加密",
    "insufficient logging & monitoring": "日志与监控不足",
    "configuration exposure":"配置信息泄露"
}

# 需要删除的正则模式（简单系统路径）
SIMPLE_PATH_PATTERNS = [
    r'\.\*?\(\?:.*?/etc/passwd.*?\)',
    r'\.\*?\(\?:.*?/windows/win\.ini.*?\)',
    r'\.\*?\(\?:.*?/win\.ini.*?\)',
    r'\.\*?\(\?:.*?/etc/shadow.*?\)',
    r'\.\*?\(\?:.*?/etc/hosts.*?\)',
    r'\.\*?\(\?:.*?/boot\.ini.*?\)',
    r'\.\*?\(\?:.*?\.\./\.\./\.\./etc/passwd.*?\)',
]


def clean_vuln_name(name):
    """
    清洗漏洞名称，返回 (clean_name, matched_type)
    如果应删除（无组件），则 clean_name 为 None
    """
    if not isinstance(name, str):
        return None, None
    # 1. 替换特殊字符
    name = re.sub(r'[<>.,\-、_]+', ' ', name)
    name = re.sub(r'\s+', ' ', name).strip()
    # 2. 删除“未翻译”和“漏洞”
    name = name.replace('未翻译', '').replace('漏洞', '')
    name = re.sub(r'\s+', ' ', name).strip()
    if not name:
        return None, None

    original_name = name
    name_lower = name.lower()

    # 3. 查找匹配的漏洞类型
    matched_type = None
    matched_key = None
    for eng, chi in VULN_MAPPING.items():
        if re.search(r'\b' + re.escape(eng) + r'\b', name_lower):
            matched_type = chi
            matched_key = eng
            break
    if not matched_type:
        # 未匹配到任何漏洞类型，保留原名称，类型为"无"
        return name, "无"

    # 删除匹配到的英文关键词
    name_without_key = re.sub(r'\b' + re.escape(matched_key) + r'\b', '', name_lower)
    name_without_key = re.sub(r'\s+', ' ', name_without_key).strip()

    # 提取组件
    if not name_without_key:
        return None, None
    if ' - ' in original_name:
        component = original_name.split(' - ')[0].strip()
    else:
        component = name_without_key.split()[0] if name_without_key.split() else None

    if not component:
        return None, None

    # 最终格式：组件 标准漏洞类型
    return f"{component} {matched_type}", matched_type


def simplify_regex(pattern):
    """简化正则表达式中重复的选项"""
    if not isinstance(pattern, str):
        return pattern

    def simplify_group(match):
        inner = match.group(1)
        parts = inner.split('|')
        unique_parts = []
        for p in parts:
            if p not in unique_parts:
                unique_parts.append(p)
        if len(unique_parts) == 1:
            return f'(?:{unique_parts[0]})'
        else:
            return f'(?:{"|".join(unique_parts)})'

    while True:
        new_pattern = re.sub(r'\(\?:([^)]+)\)', simplify_group, pattern)
        if new_pattern == pattern:
            break
        pattern = new_pattern
    return pattern


def should_keep_by_regex(pattern):
    """判断正则是否应保留"""
    if not isinstance(pattern, str):
        return True
    if re.search(r'[?&=]', pattern):
        return True
    for simple_pattern in SIMPLE_PATH_PATTERNS:
        if re.search(simple_pattern, pattern, re.IGNORECASE):
            return False
    return True


def process_file(file_path):
    """处理单个 Excel 文件，返回 DataFrame"""
    try:
        df = pd.read_excel(file_path, sheet_name="Sheet1")
    except Exception as e:
        print(f"  读取失败 {file_path}: {e}")
        return None

    # 确定原始漏洞名称列
    if '漏洞中文名称(新)' in df.columns:
        vuln_name_col = '漏洞中文名称(新)'
    elif '漏洞名称' in df.columns:
        vuln_name_col = '漏洞名称'
    else:
        print(f"  文件 {file_path} 缺少漏洞名称列，跳过")
        return None

    if '正则字符串(直接复制)' not in df.columns:
        print(f"  文件 {file_path} 缺少列 '正则字符串(直接复制)'，跳过")
        return None

    if '所有路径(原始)' not in df.columns:
        df['所有路径(原始)'] = ''

    results = []
    for idx, row in df.iterrows():
        vuln_name = row[vuln_name_col]
        pattern = row['正则字符串(直接复制)']
        path = row['所有路径(原始)'] if pd.notna(row['所有路径(原始)']) else ''

        clean_name, vuln_type = clean_vuln_name(vuln_name)
        if clean_name is None:
            continue
        simplified_pattern = simplify_regex(pattern)
        if not should_keep_by_regex(simplified_pattern):
            continue

        results.append({
            '漏洞中文名称(新)': clean_name,
            '正则字符串(直接复制)': simplified_pattern,
            '所有路径(原始)': path,
            '漏洞类型': vuln_type,
            '来源文件': os.path.basename(file_path)  # 只存文件名
        })

    if not results:
        return None
    return pd.DataFrame(results)


def main():
    folders = ["poc_luru", "poc_luru2", "fscan_poc"]
    all_files = []
    for folder in folders:
        if os.path.isdir(folder):
            files = glob(os.path.join(folder, "**", "*.xlsx"), recursive=True)
            all_files.extend(files)
        else:
            print(f"警告：文件夹 {folder} 不存在")

    if not all_files:
        print("未找到任何 Excel 文件，请检查文件夹名称和路径。")
        return

    print(f"找到 {len(all_files)} 个 Excel 文件，开始处理...")

    all_dfs = []
    for file_path in all_files:
        print(f"处理: {file_path}")
        df = process_file(file_path)
        if df is not None:
            all_dfs.append(df)

    if not all_dfs:
        print("没有有效数据可合并。")
        return

    merged = pd.concat(all_dfs, ignore_index=True)
    # 全局去重（基于中文名称和正则）
    merged = merged.drop_duplicates(subset=['漏洞中文名称(新)', '正则字符串(直接复制)'], keep='first')

    # 排序：漏洞类型为“无”的放在最后，其他按漏洞类型排序，同类型内按名称排序
    merged['_sort_key'] = merged['漏洞类型'].apply(lambda t: 0 if t != '无' else 1)
    merged = merged.sort_values(['_sort_key', '漏洞类型', '漏洞中文名称(新)'])
    merged = merged.drop(columns=['_sort_key'])

    # 调整列顺序
    cols = ['漏洞中文名称(新)', '正则字符串(直接复制)', '所有路径(原始)', '漏洞类型', '来源文件']
    merged = merged[cols]

    output_file = "poc_final_fscan_nuclei.xlsx"
    merged.to_excel(output_file, index=False, engine='openpyxl')
    print(f"\n处理完成！共保留 {len(merged)} 条记录，已保存至 {output_file}")


if __name__ == "__main__":
    main()