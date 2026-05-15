#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import yaml
import pandas as pd
from itertools import product
from multiprocessing import Pool, cpu_count
from functools import partial
from tqdm import tqdm
import shutil


# ====================== 清理控制字符 ======================
def sanitize_for_excel(obj):
    """递归清理对象中的字符串，将退格符替换为字面 \b，移除其他控制字符"""
    if isinstance(obj, str):
        obj = obj.replace('\x08', '\\b')
        import string
        control_chars = ''.join(chr(c) for c in range(0, 32) if chr(c) not in '\n\r\t')
        for ch in control_chars:
            obj = obj.replace(ch, '')
        return obj
    elif isinstance(obj, dict):
        return {k: sanitize_for_excel(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_excel(item) for item in obj]
    else:
        return obj


# ====================== 中英文字段映射 ======================
FIELD_MAPPING = {
    "id": "漏洞中文名称",
    "name": "漏洞名称",
    "author": "作者",
    "severity": "严重程度",
    "description": "描述",
    "reference": "参考链接",
    "tags": "标签",
    "classification": "分类",
    "cvss-metrics": "CVSS度量",
    "cvss-score": "CVSS分数",
    "cwe-id": "CWE编号",
    "metadata": "元数据",
}


def translate_key(key):
    return FIELD_MAPPING.get(key, key)


# ====================== 提取所有 raw 字段内容 ======================
def extract_all_raw_contents(obj, collected=None):
    if collected is None:
        collected = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "raw":
                if isinstance(v, str):
                    collected.append(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            collected.append(item)
                        else:
                            extract_all_raw_contents(item, collected)
                else:
                    extract_all_raw_contents(v, collected)
            else:
                extract_all_raw_contents(v, collected)
    elif isinstance(obj, list):
        for item in obj:
            extract_all_raw_contents(item, collected)
    return collected


# ====================== 路径提取 ======================
def extract_paths_from_raw(raw_text):
    paths = []
    if not isinstance(raw_text, str):
        return paths
    lines = raw_text.strip().splitlines()
    if not lines:
        return paths
    first_line = lines[0].strip()
    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d+\.\d+", first_line, re.IGNORECASE)
    if match:
        path = match.group(2)
        path = re.sub(r'^\{\{.*?\}\}', '', path)
        if path:
            paths.append(path)
    return paths


def find_all_paths(obj):
    paths = set()
    if isinstance(obj, dict):
        if "path" in obj:
            path_val = obj["path"]
            if isinstance(path_val, str):
                p = re.sub(r'^\{\{.*?\}\}', '', path_val.strip())
                if p:
                    paths.add(p)
            elif isinstance(path_val, list):
                for p in path_val:
                    if isinstance(p, str):
                        p = re.sub(r'^\{\{.*?\}\}', '', p.strip())
                        if p:
                            paths.add(p)
        if "raw" in obj:
            raw_val = obj["raw"]
            if isinstance(raw_val, list):
                for raw_item in raw_val:
                    if isinstance(raw_item, str):
                        for p in extract_paths_from_raw(raw_item):
                            paths.add(p)
            elif isinstance(raw_val, str):
                for p in extract_paths_from_raw(raw_val):
                    paths.add(p)
        for v in obj.values():
            paths.update(find_all_paths(v))
    elif isinstance(obj, list):
        for item in obj:
            paths.update(find_all_paths(item))
    return paths


# ====================== 变量处理 ======================
def extract_set_vars(data):
    vars_data = data.get("set", {})
    result = {}
    for k, v in vars_data.items():
        if isinstance(v, list):
            result[k] = [str(x) for x in v]
        else:
            result[k] = [str(v)]
    return result


def expand_path_variables(path_template, set_vars):
    var_names = re.findall(r"\{\{([^}]+)\}\}", path_template)
    if not var_names:
        return [path_template]
    var_values = []
    for var_name in var_names:
        if var_name in set_vars:
            var_values.append(set_vars[var_name])
        else:
            return [path_template]
    combinations = product(*var_values)
    expanded = []
    for combo in combinations:
        path = path_template
        for var_name, value in zip(var_names, combo):
            path = path.replace(f"{{{{{var_name}}}}}", value)
        expanded.append(path)
    return expanded


def replace_special_vars_to_regex(func_str):
    func_str = re.sub(r"randomLowercase\((\d+)\)", r"[a-z]{\1}", func_str)
    func_str = re.sub(r"randomNumeric\((\d+)\)", r"[0-9]{\1}", func_str)
    return func_str


def generate_regex_from_paths(all_paths):
    if not all_paths:
        return ""
    unique_paths = list(set(all_paths))
    unique_paths.sort(key=lambda x: len(x), reverse=True)
    processed = []
    for path in unique_paths:
        var_pattern = r'(\{\{[^}]+\}\})'
        var_placeholders = []

        def var_repl(match):
            var_placeholders.append(match.group(1))
            return f'__VAR_{len(var_placeholders) - 1}__'

        temp_path = re.sub(var_pattern, var_repl, path)
        func_pattern = r'(randomLowercase\(\d+\)|randomNumeric\(\d+\))'
        func_placeholders = []

        def func_repl(match):
            func_placeholders.append(match.group(1))
            return f'__FUNC_{len(func_placeholders) - 1}__'

        temp_path = re.sub(func_pattern, func_repl, temp_path)
        escaped = re.sub(r'([.?*+|(){}[\]^$\\])', r'\\\1', temp_path)
        for i in range(len(var_placeholders)):
            escaped = escaped.replace(f'__VAR_{i}__', '.*?')
        for i, func in enumerate(func_placeholders):
            regex_pattern = replace_special_vars_to_regex(func)
            escaped = escaped.replace(f'__FUNC_{i}__', regex_pattern)
        processed.append(escaped)
    combined = "|".join(processed)
    return f".*?(?:{combined}).*"


# ====================== 读取无效路径文件 ======================
def load_invalid_paths(filepath="invalid_path.txt"):
    invalid_set = set()
    if not os.path.exists(filepath):
        print(f"⚠️ 未找到无效路径文件: {filepath}，所有路径将标记为「否」")
        return invalid_set
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                invalid_set.add(line)
    print(f"📄 加载无效路径 {len(invalid_set)} 条")
    return invalid_set


# ====================== 提取字段 ======================
def extract_selected_fields(data, yaml_path, invalid_paths_set):
    result = {}
    result["漏洞中文名称"] = data.get("id", "无字段")
    info = data.get("info", {})
    result["漏洞名称"] = info.get("name", "无字段")
    result["作者"] = info.get("author", "无字段")
    result["严重程度"] = info.get("severity", "无字段")
    result["描述"] = info.get("description", "无字段")
    ref = info.get("reference", [])
    if isinstance(ref, list):
        result["参考链接"] = ", ".join(str(r) for r in ref) if ref else "无字段"
    else:
        result["参考链接"] = str(ref) if ref else "无字段"
    tags = info.get("tags", [])
    if isinstance(tags, list):
        result["标签"] = ", ".join(str(t) for t in tags) if tags else "无字段"
    else:
        result["标签"] = str(tags) if tags else "无字段"

    classification = info.get("classification", {})
    result["CVSS度量"] = classification.get("cvss-metrics", "无字段")
    result["CVSS分数"] = classification.get("cvss-score", "无字段")
    result["CWE编号"] = classification.get("cwe-id", "无字段")

    metadata = info.get("metadata", {})
    if metadata:
        for k, v in metadata.items():
            result[f"元数据_{k}"] = str(v) if v else "无字段"
    else:
        result["元数据"] = "无字段"

    raw_contents = extract_all_raw_contents(data)
    if raw_contents:
        result["原始请求内容"] = "\n---\n".join(raw_contents)
    else:
        result["原始请求内容"] = "无字段"

    raw_paths_set = find_all_paths(data)
    raw_paths = list(raw_paths_set)
    result["所有路径(原始)"] = "|".join(raw_paths) if raw_paths else "无字段"
    result["路径数量"] = len(raw_paths)

    has_invalid = "否"
    for p in raw_paths:
        if p in invalid_paths_set:
            has_invalid = "是"
            break
    result["是否无效字段"] = has_invalid

    set_vars = extract_set_vars(data)
    all_expanded_paths = []
    for p in raw_paths:
        expanded = expand_path_variables(p, set_vars)
        all_expanded_paths.extend(expanded)
    all_expanded_paths = list(set(all_expanded_paths))
    regex = generate_regex_from_paths(all_expanded_paths) if all_expanded_paths else ""
    result["正则字符串(直接复制)"] = regex if regex else "无字段"

    result["来源文件"] = os.path.basename(yaml_path)
    result["解析状态"] = "解析成功"

    return sanitize_for_excel(result)


# ====================== 解析单个YAML ======================
def parse_single_yaml(yaml_path, invalid_paths_set):
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError("YAML内容不是字典格式")
        return extract_selected_fields(data, yaml_path, invalid_paths_set)
    except yaml.YAMLError as e:
        return {
            "漏洞中文名称": os.path.basename(yaml_path).replace(".yml", "").replace(".yaml", ""),
            "漏洞名称": "无字段",
            "作者": "无字段",
            "严重程度": "无字段",
            "描述": "无字段",
            "参考链接": "无字段",
            "标签": "无字段",
            "CVSS度量": "无字段",
            "CVSS分数": "无字段",
            "CWE编号": "无字段",
            "元数据": "无字段",
            "原始请求内容": "无字段",
            "所有路径(原始)": "无字段",
            "路径数量": 0,
            "是否无效字段": "未知",
            "正则字符串(直接复制)": "无字段",
            "来源文件": os.path.basename(yaml_path),
            "解析状态": f"YAML解析失败: {str(e)}",
        }
    except Exception as e:
        return {
            "漏洞中文名称": os.path.basename(yaml_path).replace(".yml", "").replace(".yaml", ""),
            "漏洞名称": "无字段",
            "作者": "无字段",
            "严重程度": "无字段",
            "描述": "无字段",
            "参考链接": "无字段",
            "标签": "无字段",
            "CVSS度量": "无字段",
            "CVSS分数": "无字段",
            "CWE编号": "无字段",
            "元数据": "无字段",
            "原始请求内容": "无字段",
            "所有路径(原始)": "无字段",
            "路径数量": 0,
            "是否无效字段": "未知",
            "正则字符串(直接复制)": "无字段",
            "来源文件": os.path.basename(yaml_path),
            "解析状态": f"解析失败: {str(e)}",
        }


# ====================== 生成带前缀的Excel文件名 ======================
def get_excel_name_for_dir(dir_path, root_dir):
    """根据目录相对于根目录的路径，生成Excel文件名"""
    rel = os.path.relpath(dir_path, root_dir)
    if rel == '.':
        return "POC解析结果.xlsx"
    else:
        # 将路径分隔符替换为下划线
        safe = rel.replace(os.sep, '_')
        return f"{safe}_POC解析结果.xlsx"


# ====================== 处理单个文件夹 ======================
def process_folder(folder_path, invalid_paths_set, root_dir, target_dir_name):
    """处理单个文件夹：扫描YAML文件，多进程解析，生成带前缀的Excel，并立即复制到汇总目录"""
    # 收集当前目录下的YAML文件（不包括子目录）
    yaml_files = []
    for fn in os.listdir(folder_path):
        full_path = os.path.join(folder_path, fn)
        if os.path.isfile(full_path) and fn.lower().endswith(('.yml', '.yaml')):
            yaml_files.append(full_path)

    if not yaml_files:
        return

    # 打印详细信息
    print(f"\n📂 处理目录: {folder_path}")
    print(f"   找到 {len(yaml_files)} 个 YAML 文件: {', '.join(os.path.basename(f) for f in yaml_files)}")

    # 多进程解析
    # with Pool(processes=cpu_count()) as pool:
    with Pool(processes=1) as pool:
        func = partial(parse_single_yaml, invalid_paths_set=invalid_paths_set)
        results = []
        for res in tqdm(pool.imap_unordered(func, yaml_files), total=len(yaml_files),
                        desc=f"   解析进度", leave=False):
            results.append(res)

    if results:
        base_columns = [
            "漏洞中文名称", "漏洞名称", "严重程度", "描述", "作者", "参考链接", "标签",
            "CVSS度量", "CVSS分数", "CWE编号", "元数据",
            "原始请求内容",
            "所有路径(原始)", "路径数量", "正则字符串(直接复制)", "是否无效字段",
            "来源文件", "解析状态"
        ]
        all_columns = set(base_columns)
        for row in results:
            all_columns.update(row.keys())
        extra_columns = sorted([c for c in all_columns if c not in base_columns])
        final_columns = base_columns + extra_columns
        df = pd.DataFrame(results, columns=final_columns)

        # 生成Excel文件名（带路径前缀）
        excel_name = get_excel_name_for_dir(folder_path, root_dir)
        output_file = os.path.join(folder_path, excel_name)
        df.to_excel(output_file, index=False, engine="openpyxl")

        success_count = len(df[df["解析状态"] == "解析成功"])
        total_paths = df[df["解析状态"] == "解析成功"]["路径数量"].sum() if success_count > 0 else 0
        print(f"   ✅ 生成 {excel_name} (成功 {success_count}/{len(results)} 个，总路径 {total_paths})")

        # 边解析边保存：复制到汇总目录
        target_dir = os.path.join(root_dir, target_dir_name)
        os.makedirs(target_dir, exist_ok=True)
        dst_file = os.path.join(target_dir, excel_name)
        # 如果汇总目录已存在同名文件，添加数字后缀（一般不会发生，因为路径前缀唯一）
        if os.path.exists(dst_file):
            base, ext = os.path.splitext(excel_name)
            counter = 1
            while os.path.exists(os.path.join(target_dir, f"{base}_{counter}{ext}")):
                counter += 1
            dst_file = os.path.join(target_dir, f"{base}_{counter}{ext}")
            print(f"   ⚠️ 汇总目录已存在 {excel_name}，将保存为 {os.path.basename(dst_file)}")
        shutil.copy2(output_file, dst_file)
        print(f"   📎 已汇总到 {target_dir_name}/{os.path.basename(dst_file)}")


# ====================== 主函数 ======================
def main(root_dir, invalid_paths_set, target_dir_name="poc_allV1"):
    if not os.path.exists(root_dir):
        print(f"❌ 根目录不存在: {root_dir}")
        return

    dirs_to_process = []

    # 递归遍历所有子目录，跳过汇总目录自身
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 排除汇总目录
        if target_dir_name in dirnames:
            dirnames.remove(target_dir_name)
        # 检查当前目录是否直接包含 YAML 文件
        yaml_files = [f for f in filenames if f.lower().endswith(('.yml', '.yaml'))]
        if yaml_files:
            dirs_to_process.append(dirpath)

    if not dirs_to_process:
        print("⚠️ 未找到任何包含 YAML 文件的目录")
        return

    print(f"📁 找到 {len(dirs_to_process)} 个包含 YAML 文件的目录:")
    for d in dirs_to_process:
        print(f"   - {d}")

    print("\n开始处理...")
    for dirpath in tqdm(dirs_to_process, desc="处理文件夹"):
        process_folder(dirpath, invalid_paths_set, root_dir, target_dir_name)
    print("\n✅ 所有文件夹处理完成！")


# ====================== 运行 ======================
if __name__ == "__main__":
    ROOT_DIR = r"./poc"               # 存放YAML文件的根目录
    INVALID_FILE = "invalid_path.txt"
    TARGET_SUMMARY_DIR = "poc_allV1"

    invalid_paths = load_invalid_paths(INVALID_FILE)
    main(ROOT_DIR, invalid_paths, TARGET_SUMMARY_DIR)