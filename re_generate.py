import pandas as pd
import re
import os

# ====================== 配置参数（可根据实际路径修改） ======================
EXCEL_INPUT_PATH = "path_original.xlsx"  # 输入Excel路径
EXCEL_OUTPUT_PATH = "path_processed.xlsx"  # 输出Excel路径（处理后保存）
INVALID_PATH_FILE = "invalid_path.txt"  # invalid_path.txt路径
TARGET_HEADER = "所有路径(原始)"  # 目标表头：所有路径(原始)


def load_invalid_paths(file_path):
    """加载invalid_path.txt中的无效路径，返回去重后的集合（用于精确匹配）"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"❌ 未找到invalid_path.txt文件：{file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        # 读取所有内容，按空白字符（空格/换行）分割，去重后生成集合
        invalid_paths = set()
        for line in f:
            # 分割每行内容（处理空格/制表符分隔），并清理前后空白
            paths = [p.strip() for p in line.split() if p.strip()]
            invalid_paths.update(paths)

    print(f"✅ 加载无效路径 {len(invalid_paths)} 条：{invalid_paths}")
    return invalid_paths


def clean_backslash_before_pipe(path_str):
    """清理|前面的所有反斜杠（\、\\、\\\\等），返回清理后的字符串"""
    if pd.isna(path_str) or path_str == "":
        return ""

    # 正则匹配：一个或多个反斜杠(\)后面跟|，替换为仅保留|
    # 正则解释：\\+ 匹配1个及以上反斜杠，(\|) 捕获|，替换为捕获的|
    cleaned_str = re.sub(r'\\+(\|)', r'\1', str(path_str))
    return cleaned_str


def filter_and_deduplicate(path_str, invalid_paths):
    """
    1. 按|分割路径
    2. 过滤掉在invalid_paths中的路径
    3. 去重
    4. 用|拼接返回
    """
    if pd.isna(path_str) or path_str == "":
        return ""

    # 按|分割，清理每个路径的前后空白
    path_list = [p.strip() for p in path_str.split("|") if p.strip()]

    # 过滤无效路径（精确匹配）
    filtered_list = [p for p in path_list if p not in invalid_paths]

    # 去重（保持原顺序，用dict.fromkeys保留首次出现的元素）
    deduplicated_list = list(dict.fromkeys(filtered_list))

    # 用|拼接
    result_str = "|".join(deduplicated_list)
    return result_str


def generate_regex(path_str):
    """根据处理后的路径字符串（|分隔）生成对应的正则表达式"""
    if pd.isna(path_str) or path_str == "":
        return ""

    # 按|分割路径
    path_list = [p.strip() for p in path_str.split("|") if p.strip()]
    if not path_list:
        return ""

    # 转义每个路径的正则特殊字符（.、?、&、\等）
    escaped_paths = [re.escape(p) for p in path_list]

    # 生成正则：.*?(?:路径1|路径2|...).*
    regex = f".*?(?:{'|'.join(escaped_paths)}).*"
    return regex


def process_excel(invalid_paths):
    """读取Excel，处理目标列，生成结果并保存"""
    # 读取Excel
    try:
        df = pd.read_excel(EXCEL_INPUT_PATH)
    except Exception as e:
        raise Exception(f"❌ 读取Excel失败：{str(e)}")

    # 检查目标表头是否存在
    if TARGET_HEADER not in df.columns:
        raise ValueError(f"❌ Excel中未找到表头：{TARGET_HEADER}，请检查表头名称")

    print(f"✅ 读取Excel成功，共 {len(df)} 行数据，开始处理...")

    # 分步处理：1. 清理反斜杠 2. 过滤无效路径+去重 3. 生成正则
    df["处理后路径（去重+过滤）"] = df[TARGET_HEADER].apply(clean_backslash_before_pipe).apply(
        lambda x: filter_and_deduplicate(x, invalid_paths)
    )
    df["正则字符串(直接复制)"] = df["处理后路径（去重+过滤）"].apply(generate_regex)

    # 保存处理后的Excel
    try:
        df.to_excel(EXCEL_OUTPUT_PATH, index=False, engine="openpyxl")
        print(f"✅ 处理完成！结果已保存到：{EXCEL_OUTPUT_PATH}")
    except Exception as e:
        raise Exception(f"❌ 保存Excel失败：{str(e)}")

    # 输出处理统计
    total_rows = len(df)
    non_empty_result = len(df[df["处理后路径（去重+过滤）"] != ""])
    print(f"\n📊 处理统计：")
    print(f"   - 总数据行数：{total_rows}")
    print(f"   - 有效处理行数（非空）：{non_empty_result}")
    print(f"   - 空数据行数：{total_rows - non_empty_result}")

    return df


if __name__ == "__main__":
    try:
        print("=" * 60)
        print("📋 开始路径处理流程...")
        print("=" * 60)

        # 1. 加载无效路径
        invalid_paths = load_invalid_paths(INVALID_PATH_FILE)

        # 2. 处理Excel并生成结果
        result_df = process_excel(invalid_paths)

        print("\n" + "=" * 60)
        print("🎉 所有流程执行完成！")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 程序执行失败：{str(e)}")