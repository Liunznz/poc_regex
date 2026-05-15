import pandas as pd
import re
import os

# ========== 1. 漏洞类型 → 必需攻击特征（正则片段，小写） ==========
# 说明：每条规则至少应匹配其中任意一个特征，否则可能误报
ATTACK_PATTERNS = {
    "SQL注入": [
        r"['\"]\s*(?:union|sleep|extractvalue|updatexml|benchmark|waitfor|and|or|xor|like|between|in)\b",
        r"(\bunion\b.*\bselect\b)",
        r"\b(?:extractvalue|updatexml|benchmark|sleep)\s*\(",
        r"waitfor\s+delay",
        r"md5\s*\(",
        r"concat\s*\(",
        r"0x[0-9a-f]{2,}",
        r"\b(?:into\s+outfile|into\s+dumpfile)\b",
        r"--\s+[\w-]",
        r"%20(?:or|and)%20",
        r"'+.*?'.*?or",
    ],
    "跨站脚本": [
        r"<script",
        r"alert\s*\(",
        r"confirm\s*\(",
        r"prompt\s*\(",
        r"onerror\s*=",
        r"onload\s*=",
        r"onmouseover\s*=",
        r"javascript\s*:",
        r"<img",
        r"<svg",
        r"<iframe",
        r"document\.(cookie|domain)",
        r"&#x?\d+;",
    ],
    "命令执行|代码执行|远程命令执行|远程代码执行": [
        r"\b(?:exec|system|passthru|shell_exec|popen|proc_open|eval|assert)\s*\(",
        r"`.*?`",
        r"\$\{.*?\}",
        r"\|.*?\|",
        r";\s*(?:ls|dir|id|whoami|cat|echo|ping|wget|curl|nslookup|ipconfig|ifconfig)",
        r"&{2}",
        r"\$\(.*?\)",
        r"base64_decode\s*\(",
        r"cmd\s*=",
    ],
    "任意文件上传": [
        r"upload",
        r"file\s*=",
        r"filename\s*=",
        r"multipart/form-data",
        r"\.php",
        r"\.jsp",
        r"writefile",
    ],
    "任意文件读取|文件读取|文件包含|本地文件包含|路径遍历": [
        r"\.\./",
        r"\.\.\\",
        r"file://",
        r"readfile",
        r"fopen",
        r"\.\.%2f",
        r"\.\.%5c",
        r"etc/passwd",
        r"windows/win\.ini",
        r"proc/self/environ",
    ],
    "信息泄露": [
        r"\.(?:git|svn|env|log|config|conf|ini|yaml|yml|json|xml|db|sql|bak|backup|old|swp|swo|poc|temp)",
        r"phpinfo\s*\(",
        r"composer\.json",
        r"package\.json",
    ],
    "服务端请求伪造": [
        r"url\s*=",
        r"http[s]?://",
        r"fetch",
        r"proxy",
        r"ssrf",
    ],
    "开放重定向": [
        r"redirect",
        r"next\s*=",
        r"return\s*=",
        r"callback\s*=",
        r"url\s*=",
        r"location\s*=",
    ],
    "XML外部实体注入": [
        r"<!ENTITY",
        r"DOCTYPE",
        r"xml\.",
        r"xxe",
    ],
    "反序列化": [
        r"deserialize",
        r"ObjectInputStream",
        r"readObject",
        r"base64",
        r"yaml",
    ],
    "目录遍历": [
        r"\.\./",
        r"\.\.\\",
        r"\.\.%2f",
        r"\.\.%5c",
    ],
}
# 补充一些通用的攻击特征（任何类型都应该有至少一个）
GENERIC_ATTACK = [
    r"\{\{.*?\}\}",          # 模板注入变量
    r"\$\{.*?\}",            # JNDI/EL表达式
    r"@\w+\.",               # Java注解等
]

# ========== 2. 辅助函数 ==========
def get_vuln_type_key(vuln_type):
    """匹配漏洞类型到攻击特征映射的键（支持模糊匹配）"""
    if not isinstance(vuln_type, str):
        return None
    vt_lower = vuln_type.lower()
    for key in ATTACK_PATTERNS.keys():
        if re.search(key, vt_lower):
            return key
    return None

def has_attack_feature(pattern, vuln_type_key, vuln_type_original):
    """检查正则是否包含任何攻击特征"""
    if not isinstance(pattern, str) or pd.isna(pattern):
        return False, "规则为空"
    pattern_lower = pattern.lower()
    # 先检查通用特征
    for pat in GENERIC_ATTACK:
        if re.search(pat, pattern_lower):
            return True, "包含通用攻击特征"
    # 根据漏洞类型检查
    if vuln_type_key is None:
        # 未匹配到类型映射，则宽松检查（只要包含特殊字符）
        if re.search(r"['\"`]|\\x|%[0-9a-f]{2}", pattern_lower):
            return True, "包含特殊字符"
        return False, f"未识别的漏洞类型: {vuln_type_original}"
    patterns = ATTACK_PATTERNS[vuln_type_key]
    for pat in patterns:
        if re.search(pat, pattern_lower):
            return True, f"匹配特征: {pat}"
    return False, "未命中任何攻击特征"

def analyze_branches(pattern):
    """如果正则中包含 | 分隔符，逐个分支检查"""
    if not isinstance(pattern, str):
        return []
    # 简单分割：需要考虑括号内的 | 可能不是顶层分隔符，这里简化处理
    # 仅当 | 不在括号内时才分割（粗略判断）
    # 更好的方式：使用正则解析，但此处简化，先按 | 分割，然后检查每个片段是否有点特征
    # 注意：很多正则的 | 是在 (?:...) 内的，我们需要提取出所有分支
    # 本函数返回缺失特征的分支列表
    branches = []
    # 先处理带括号的分组
    # 匹配形如 (?:a|b|c) 或 (a|b) 的组
    group_pattern = r'\((?:[^()]*?)\|(?:[^()]*?)\)'  # 简单匹配含竖线的括号组
    # 提取所有这种组
    for m in re.finditer(group_pattern, pattern):
        group_content = m.group(0)
        # 去掉外层括号和可能的 ?:
        inner = re.sub(r'^\((?:\?:)?(.*)\)$', r'\1', group_content)
        if '|' in inner:
            branches.extend(inner.split('|'))
    # 如果没有找到括号内的 |，简单按 | 分割
    if not branches and '|' in pattern:
        # 避免分割过度，只取顶层（不含括号的）
        # 简单做法：按 | 分割，尽量保留原始片段
        parts = pattern.split('|')
        for p in parts:
            # 如果 p 不包含未闭合的括号，认为是一个分支
            if p.count('(') == p.count(')'):
                branches.append(p)
    return list(set(branches))

def branch_has_feature(branch, vuln_type_key):
    """检查单个分支是否有攻击特征"""
    if not isinstance(branch, str):
        return False
    branch_lower = branch.lower()
    for pat in GENERIC_ATTACK:
        if re.search(pat, branch_lower):
            return True
    if vuln_type_key is None:
        return False
    patterns = ATTACK_PATTERNS.get(vuln_type_key, [])
    for pat in patterns:
        if re.search(pat, branch_lower):
            return True
    return False

# ========== 3. 主处理 ==========
def main():
    input_file = "poc_final_fscan_nuclei_cleanedV3.xlsx"
    output_file = "正则风险分析报告.xlsx"
    
    if not os.path.exists(input_file):
        print(f"错误: 找不到文件 {input_file}")
        return
    
    df = pd.read_excel(input_file, sheet_name="Sheet1")
    # 保留所有原始列，新增分析列
    results = []
    
    for idx, row in df.iterrows():
        vuln_type = row.get("漏洞类型", "")
        pattern = row.get("正则字符串(直接复制)", "")
        vuln_name = row.get("漏洞中文名称", "")
        component = row.get("组件", "")
        
        # 获取匹配的漏洞类型键
        vuln_key = get_vuln_type_key(vuln_type)
        
        # 整体检查
        has_feature, reason = has_attack_feature(pattern, vuln_key, vuln_type)
        
        risk = "低风险"
        suggestions = ""
        weak_branches = []
        
        if not has_feature:
            risk = "高风险 （缺少攻击特征）"
            suggestions = "建议检查正则是否过于宽泛，添加该漏洞类型的典型攻击payload特征。"
            # 进一步分析分支
            branches = analyze_branches(pattern)
            if branches:
                weak = []
                for br in branches:
                    if not branch_has_feature(br, vuln_key):
                        weak.append(br[:80])  # 截断过长的分支
                if weak:
                    weak_branches = weak
                    suggestions += f" 以下分支缺少特征: {weak}"
        else:
            # 即使有特征，也可能有弱分支
            branches = analyze_branches(pattern)
            if branches:
                weak = []
                for br in branches:
                    if not branch_has_feature(br, vuln_key):
                        weak.append(br[:80])
                if weak:
                    risk = "中风险 （存在弱分支）"
                    suggestions = f"部分分支缺少攻击特征，可能导致误报: {weak}"
        
        results.append({
            "组件": component,
            "漏洞中文名称": vuln_name,
            "漏洞类型": vuln_type,
            "正则字符串(直接复制)": pattern,
            "风险等级": risk,
            "检查结果": reason if has_feature else "无攻击特征",
            "存在弱点的分支": "; ".join(weak_branches) if weak_branches else "",
            "优化建议": suggestions,
            "原始行号": idx + 2  # Excel行号
        })
    
    result_df = pd.DataFrame(results)
    result_df.to_excel(output_file, index=False)
    print(f"分析完成！结果已保存到 {output_file}")
    print(f"共分析 {len(results)} 条规则")
    high_risk = result_df[result_df["风险等级"].str.contains("高风险")]
    print(f"高风险规则数: {len(high_risk)}")
    print("建议重点关注高风险规则，根据建议进行优化。")

if __name__ == "__main__":
    main()