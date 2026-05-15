import os
import re
import pandas as pd

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

def escape_pipe(s):
    """将字符串中的 | 转义为 \|"""
    if not isinstance(s, str):
        return s
    return s.replace('|', r'\|')

def remove_version(vuln_name):
    """去除漏洞名称中的版本号"""
    if not isinstance(vuln_name, str):
        return vuln_name
    pattern = r'\s*(?:<=|>=|=|v)?\s*[\d\.]+(?:[a-zA-Z]*)?\s*'
    name = re.sub(pattern, ' ', vuln_name)
    name = re.sub(r'\s+', ' ', name).strip()
    name = re.sub(r'\s*-\s*', ' - ', name)
    return name

def translate_vuln_name(cleaned_name):
    """翻译漏洞名称，返回 (中文名, 是否成功)"""
    preprocessed = re.sub(r'[_\-\=]', ' ', cleaned_name).lower()
    matched = False
    chinese_type = None
    for eng, chi in VULN_MAPPING.items():
        if re.search(r'\b' + re.escape(eng) + r'\b', preprocessed):
            chinese_type = chi
            matched = True
            break
    if matched and chinese_type:
        parts = cleaned_name.split('-', 1)
        if len(parts) == 2:
            component = parts[0].strip()
            return f"{component} - {chinese_type}", True
        else:
            return f"{cleaned_name} - {chinese_type}", True
    else:
        return f"{cleaned_name} - 未翻译", False

def merge_with_pipe(series, sep='|', escape=True):
    """将Series中的多个字符串用 sep 连接，可选对每个元素中的分隔符进行转义"""
    parts = []
    for val in series.dropna():
        if not isinstance(val, str):
            val = str(val)
        if escape:
            val = escape_pipe(val)
        parts.append(val)
    # 去重保持顺序
    unique = list(dict.fromkeys(parts))
    return sep.join(unique)

def process_one_excel(file_path, invalid_paths_set):
    """处理单个Excel文件，返回 (已翻译有效DataFrame, 未翻译或无效路径DataFrame)"""
    df = pd.read_excel(file_path, sheet_name="Sheet1")
    # 删除所有路径中包含 /wp-content 的行
    if '所有路径(原始)' in df.columns:
        df = df[~df['所有路径(原始)'].astype(str).str.contains('/wp-content', na=False)]
    else:
        print(f"  警告：文件缺少 '所有路径(原始)' 列，跳过过滤")
        return None, None

    if df.empty:
        return None, None

    if '漏洞名称' not in df.columns or '正则字符串(直接复制)' not in df.columns:
        print(f"  错误：文件缺少必要列")
        return None, None

    df['cleaned_name'] = df['漏洞名称'].apply(remove_version)

    # 第一次分组：按 cleaned_name 合并（使用 | 分隔，并对内容中的 | 转义）
    # 需要将正则字符串和路径都合并（路径也可能有 |，一并转义）
    def merge_pattern(series):
        return merge_with_pipe(series, sep='|', escape=True)
    agg_dict = {col: 'first' for col in df.columns if col not in ['cleaned_name', '正则字符串(直接复制)', '所有路径(原始)']}
    agg_dict['正则字符串(直接复制)'] = merge_pattern
    agg_dict['所有路径(原始)'] = merge_pattern   # 路径同样用 | 合并并转义
    grouped = df.groupby('cleaned_name', as_index=False).agg(agg_dict)

    # 翻译
    translated_names = []
    translation_success = []
    for _, row in grouped.iterrows():
        trans, succ = translate_vuln_name(row['cleaned_name'])
        translated_names.append(trans)
        translation_success.append(succ)

    grouped['漏洞中文名称(新)'] = translated_names
    grouped['是否翻译成功'] = translation_success

    # 标记无效路径
    if '所有路径(原始)' in grouped.columns:
        grouped['是无效路径'] = grouped['所有路径(原始)'].astype(str).isin(invalid_paths_set)
    else:
        grouped['是无效路径'] = False

    # 拆分数据
    trans_df = grouped[(grouped['是否翻译成功'] == True) & (grouped['是无效路径'] == False)].copy()
    untrans_df = grouped[(grouped['是否翻译成功'] == False) | (grouped['是无效路径'] == True)].copy()

    # 对已翻译有效数据，按中文名称再次合并正则字符串和路径（去重，使用 | 连接，转义内部 |）
    if not trans_df.empty:
        agg_dict2 = {
            '正则字符串(直接复制)': lambda x: merge_with_pipe(x, sep='|', escape=True),
            '所有路径(原始)': lambda x: merge_with_pipe(x, sep='|', escape=True),
        }
        for col in trans_df.columns:
            if col not in ['漏洞中文名称(新)', '正则字符串(直接复制)', '所有路径(原始)']:
                agg_dict2[col] = 'first'
        trans_df = trans_df.groupby('漏洞中文名称(新)', as_index=False).agg(agg_dict2)

    # 清理辅助列
    for df_out in [trans_df, untrans_df]:
        if not df_out.empty:
            df_out.drop(columns=['cleaned_name', '是否翻译成功', '是无效路径'], inplace=True, errors='ignore')
            cols = ['漏洞中文名称(新)'] + [c for c in df_out.columns if c != '漏洞中文名称(新)']
            if df_out is trans_df:
                trans_df = df_out[cols]
            elif df_out is untrans_df:
                untrans_df = df_out[cols]

    return trans_df, untrans_df

def main():
    input_dir = "poc_qian_test"
    output_dir_zh = "poc_zhV2"
    output_dir_un = "poc_notra_invalid"
    invalid_txt = "invalid_path.txt"

    if not os.path.isdir(input_dir):
        print(f"错误：找不到目录 '{input_dir}'")
        return
    os.makedirs(output_dir_zh, exist_ok=True)
    os.makedirs(output_dir_un, exist_ok=True)

    invalid_paths = set()
    if os.path.isfile(invalid_txt):
        with open(invalid_txt, 'r', encoding='utf-8') as f:
            for line in f:
                path = line.strip()
                if path:
                    invalid_paths.add(path)
        print(f"已加载 {len(invalid_paths)} 条无效路径")
    else:
        print(f"警告：未找到 {invalid_txt}，将不处理无效路径分类")

    xlsx_files = [f for f in os.listdir(input_dir) if f.endswith('.xlsx')]
    if not xlsx_files:
        print(f"在 {input_dir} 中未找到任何 .xlsx 文件")
        return

    for file in xlsx_files:
        input_path = os.path.join(input_dir, file)
        print(f"\n正在处理: {file}")
        try:
            trans_df, untrans_df = process_one_excel(input_path, invalid_paths)
            if trans_df is None and untrans_df is None:
                print(f"  无有效数据（过滤后为空），跳过生成输出文件")
                continue

            if trans_df is not None and not trans_df.empty:
                out_path = os.path.join(output_dir_zh, file)
                trans_df.to_excel(out_path, index=False, engine='openpyxl')
                print(f"  已翻译有效数据已保存: {out_path}")
            else:
                print(f"  无已翻译有效数据，不生成文件")

            if untrans_df is not None and not untrans_df.empty:
                out_path = os.path.join(output_dir_un, file)
                untrans_df.to_excel(out_path, index=False, engine='openpyxl')
                print(f"  未翻译/无效路径数据已保存: {out_path}")
            else:
                print(f"  无未翻译/无效路径数据，不生成文件")

        except Exception as e:
            print(f"  处理失败: {e}")

    print("\n全部处理完成！")

if __name__ == "__main__":
    main()