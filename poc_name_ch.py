import os
import re
import pandas as pd

# ---------- 1. 漏洞类型中英文映射表 ----------
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

def extract_vuln_type(text):
    """从文本中提取漏洞类型（英文）并返回对应的中文术语"""
    if not isinstance(text, str):
        return None
    # 优先匹配长短语
    for eng, chi in VULN_MAPPING.items():
        if re.search(re.escape(eng), text, re.IGNORECASE):
            return chi
    # 更宽松的单词边界匹配
    for eng, chi in VULN_MAPPING.items():
        if re.search(r'\b' + re.escape(eng) + r'\b', text, re.IGNORECASE):
            return chi
    return None

def extract_component_and_version(vuln_name):
    """从漏洞名称中提取组件名+版本（第一个'-'之前的部分）"""
    if not isinstance(vuln_name, str):
        return ""
    idx = vuln_name.find('-')
    if idx != -1:
        return vuln_name[:idx].strip()
    return vuln_name.strip()

def get_new_vuln_chinese(row):
    """
    根据行的信息生成新的“漏洞中文名称”列内容：
    1. 若原漏洞中文名称中包含可识别的漏洞类型，则直接保留原值。
    2. 否则，从漏洞名称中提取组件名+版本，并尝试识别漏洞类型。
    3. 若漏洞类型识别成功，返回 "组件名 - 中文漏洞类型"。
    4. 若识别失败，返回 "组件名 - [未翻译] 原始英文描述"。
    """
    # 原始漏洞中文名称（第一列）
    orig_chinese = row.iloc[0] if len(row) > 0 else ""
    # 漏洞名称（第二列）
    vuln_name = row.iloc[1] if len(row) > 1 else ""

    # 步骤1：检查原漏洞中文名称是否包含可识别的漏洞类型
    if pd.notna(orig_chinese) and isinstance(orig_chinese, str):
        vuln_type = extract_vuln_type(orig_chinese)
        if vuln_type:
            return orig_chinese  # 保留原值

    # 步骤2：处理漏洞名称
    if pd.isna(vuln_name) or not isinstance(vuln_name, str) or not vuln_name.strip():
        return "未知漏洞"

    # 提取组件名+版本（第一个'-'之前）
    component = extract_component_and_version(vuln_name)

    # 尝试从漏洞名称中识别漏洞类型
    vuln_type = extract_vuln_type(vuln_name)
    if vuln_type:
        return f"{component} - {vuln_type}"

    # 步骤3：无法识别类型，保留原始英文描述（第一个'-'之后的内容）
    parts = vuln_name.split('-', 1)
    if len(parts) == 2:
        desc_to_keep = parts[1].strip()
        if desc_to_keep:
            return f"{component} - [未翻译] {desc_to_keep}"
        else:
            return f"{component} - 未知漏洞"
    else:
        # 如果没有'-'，保留整个漏洞名称作为描述
        return f"{component} - [未翻译] {vuln_name}"

def process_excel(input_path, output_path):
    """处理单个 Excel 文件，修改第一列并保存"""
    try:
        df = pd.read_excel(input_path, sheet_name="Sheet1")
        # 应用转换函数，修改第一列（漏洞中文名称）
        df.iloc[:, 0] = df.apply(get_new_vuln_chinese, axis=1)
        # 保存
        df.to_excel(output_path, index=False, sheet_name="Sheet1")
        print(f"成功处理：{input_path} -> {output_path}")
        return True
    except Exception as e:
        print(f"处理失败 {input_path}: {e}")
        return False

def main():
    poc_root = "poc"
    if not os.path.isdir(poc_root):
        print(f"错误：找不到 '{poc_root}' 文件夹，请确保脚本与 poc 目录在同一路径下。")
        return

    output_root = "poc_all_zh"
    os.makedirs(output_root, exist_ok=True)

    for dir_name in os.listdir(poc_root):
        sub_dir = os.path.join(poc_root, dir_name)
        if not os.path.isdir(sub_dir):
            continue
        excel_file = os.path.join(sub_dir, "POC解析结果.xlsx")
        if not os.path.isfile(excel_file):
            print(f"跳过 {sub_dir}：未找到 POC解析结果.xlsx")
            continue

        output_filename = f"{dir_name}_POC解析结果.xlsx"
        output_path = os.path.join(output_root, output_filename)
        process_excel(excel_file, output_path)

    print("批量处理完成！结果保存在 poc_all_zh 文件夹中。")

if __name__ == "__main__":
    main()