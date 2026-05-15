import pandas as pd
import re
import os

# 读取 Excel
file_path = "poc_final_fscan_nuclei_cleanedV2.xlsx"
df = pd.read_excel(file_path)

# 目标漏洞类型关键词（命令执行、代码执行相关）
target_keywords = ["命令执行", "代码执行", "远程命令", "远程代码", "rce", "command injection", "code injection"]

# 筛选出相关的漏洞行
mask = df["漏洞中文名称"].astype(str).str.lower().str.contains("|".join(target_keywords), na=False)
vuln_df = df[mask].copy()

if vuln_df.empty:
    print("未找到任何命令执行/代码执行相关漏洞，退出")
    exit()

# 攻击特征词列表（用于判断正则是否包含攻击语法）
attack_patterns = [
    r"\b(?:exec|system|passthru|eval|assert|popen|proc_open|shell_exec)\b",
    r"\b(?:wget|curl|nc|telnet|ftp|ssh|scp|rsync)\b",
    r"\b(?:bash|sh|zsh|cmd|powershell)\b",
    r"\b(?:whoami|id|uname|hostname|ifconfig|ipconfig|netstat|ps|kill|chmod|chown|mount|umount)\b",
    r"\b(?:cat|grep|awk|sed|head|tail|more|less|find|xargs|sort|uniq)\b",
    r"\b(?:ping|traceroute|nslookup|dig|host|netcat|nc)\b",
    r"\b(?:python|perl|ruby|php|java|gcc|g\+\+|make)\b",
    r"\b(?:select|union|sleep|extractvalue|updatexml|into outfile|load_file)\b",
    r"[\|\&;`\$\(]",
    r"%0a|%0d",
    r"\$IFS",
    r"\|\|",
    r"&&",
    r"\$\{.*?\}",
    r"`.*?`"
]

# 普通常见参数（容易误报）
benign_params = [r"[?&]id=", r"[?&]page=", r"[?&]type=", r"[?&]action=", r"[?&]cmd=", r"[?&]c=", r"[?&]q="]

def risk_score(pattern):
    if not isinstance(pattern, str):
        return 100  # 无效正则直接给高分
    score = 0
    # 检查是否包含攻击特征
    has_attack = False
    for pat in attack_patterns:
        if re.search(pat, pattern, re.IGNORECASE):
            has_attack = True
            break
    if not has_attack:
        score += 40
    
    # 检查是否匹配普通参数名
    for param in benign_params:
        if re.search(param, pattern, re.IGNORECASE):
            score += 30
            break
    
    # 检查是否为 .*?开头 .*结尾的“万能”正则
    if pattern.startswith(".*?") and pattern.endswith(".*"):
        score += 20
    # 正则长度过短
    if len(pattern) < 30:
        score += 10
    
    # 检查是否包含边界 \b 或 ^ $ (好习惯可以减少误报)
    if re.search(r"\\b|^\\^|\\$$", pattern):
        score -= 20
    return min(score, 100)

def suggest_improvement(pattern):
    suggestions = []
    # 缺少攻击特征
    has_attack = any(re.search(p, pattern, re.IGNORECASE) for p in attack_patterns)
    if not has_attack:
        suggestions.append("添加命令执行常见特征，如 \b(exec|system|wget|curl)\b 或特殊符号 [|&;`]")
    # 匹配普通参数
    if any(re.search(p, pattern, re.IGNORECASE) for p in benign_params):
        suggestions.append("将参数匹配从 'id=' 改为 '?id=' 或增加更多攻击验证，避免误匹配业务参数")
    # 缺少边界
    if not re.search(r"\\b|^\\^|\\$$", pattern):
        suggestions.append("添加单词边界 \\b 或行首尾锚定 ^ $")
    # 长度过短且无特殊字符
    if len(pattern) < 30 and not has_attack:
        suggestions.append("正则过于宽泛，请增加具体攻击 payload 片段")
    if not suggestions:
        suggestions.append("当前正则较为安全，但仍建议用实际误报 URL 测试")
    return "; ".join(suggestions)

vuln_df["误报风险评分"] = vuln_df["正则字符串(直接复制)"].apply(risk_score)
vuln_df["修改建议"] = vuln_df["正则字符串(直接复制)"].apply(suggest_improvement)

# 筛选高风险规则（评分 >= 60）
high_risk = vuln_df[vuln_df["误报风险评分"] >= 60].copy()
high_risk = high_risk.sort_values("误报风险评分", ascending=False)

# 输出报告
output_file = "高风险规则_待审核.xlsx"
high_risk.to_excel(output_file, index=False)
print(f"已生成高风险规则报告: {output_file}")
print(f"共扫描 {len(vuln_df)} 条规则，其中高风险 {len(high_risk)} 条")