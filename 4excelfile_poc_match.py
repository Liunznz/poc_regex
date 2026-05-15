import pandas as pd

# ====================== 配置参数（无需修改，按文件路径自动匹配） ======================
# 输入文件路径
FILE_LOGIC = "./漏洞扫描逻辑整理_整理版.xlsx"  # 漏洞扫描逻辑表
FILE_POC = "./POC_最终正确版_有误报path.xlsx"  # POC有误报路径表
# 输出文件路径
OUTPUT_FILE = "./漏洞扫描逻辑_新增POC.xlsx"  # 最终筛选出的新POC表

# 关键表头（按你的需求定义）
HEADER_POC_NAME_EN = "POC名称（英）"  # 两个表中统一的POC名称（英）表头


# ====================== 步骤1：处理漏洞扫描逻辑表（删除poc-yaml-前缀） ======================
def process_logic_file(file_path):
    """读取漏洞扫描逻辑表，删除POC名称（英）的poc-yaml-前缀"""
    df = pd.read_excel(file_path)

    # 检查表头是否存在
    if HEADER_POC_NAME_EN not in df.columns:
        raise ValueError(f"漏洞扫描逻辑表缺少必要表头：{HEADER_POC_NAME_EN}")

    # 删除前缀：处理非空值，去除"poc-yaml-"
    df[HEADER_POC_NAME_EN] = df[HEADER_POC_NAME_EN].apply(
        lambda x: str(x).replace("poc-yaml-", "") if pd.notna(x) and str(x).startswith("poc-yaml-") else x
    )

    print(f"✅ 漏洞扫描逻辑表处理完成：共 {len(df)} 条数据，已删除'poc-yaml-'前缀")
    return df


# ====================== 步骤2：处理POC有误报路径表（转为字典列表） ======================
def process_poc_file(file_path):
    """读取POC表，转为字典列表（每条数据为一个字典，键为表头）"""
    df = pd.read_excel(file_path)

    # 检查表头是否存在
    if HEADER_POC_NAME_EN not in df.columns:
        raise ValueError(f"POC表缺少必要表头：{HEADER_POC_NAME_EN}")

    # 转为字典列表（orient='records' 按行转字典）
    poc_dict_list = df.to_dict(orient="records")
    # 提取POC名称（英）的集合，用于后续匹配
    poc_name_set = {str(item[HEADER_POC_NAME_EN]) for item in poc_dict_list if pd.notna(item[HEADER_POC_NAME_EN])}

    print(f"✅ POC表处理完成：共 {len(poc_dict_list)} 条数据，提取 {len(poc_name_set)} 个POC名称")
    return poc_dict_list, poc_name_set


# ====================== 步骤3：对比匹配，筛选新POC（漏洞表有、POC表无） ======================
def filter_new_poc(logic_df, poc_name_set):
    """筛选漏洞扫描逻辑表中，POC名称（英）不在POC表中的数据"""

    # 定义匹配函数：判断漏洞表的POC名称是否在POC表的名称集合中
    def is_new_poc(poc_name):
        if pd.isna(poc_name):
            return False  # 空值视为不匹配
        return str(poc_name) not in poc_name_set

    # 筛选新POC数据
    new_poc_df = logic_df[logic_df[HEADER_POC_NAME_EN].apply(is_new_poc)].copy()

    # 转为字典列表（按需求输出键值对列表）
    new_poc_list = new_poc_df.to_dict(orient="records")

    print(f"✅ 对比完成：漏洞表共 {len(logic_df)} 条数据，筛选出 {len(new_poc_list)} 条新POC数据")
    return new_poc_df, new_poc_list


# ====================== 步骤4：保存新POC到Excel ======================
def save_new_poc(new_poc_df, output_path):
    """将筛选出的新POC数据保存到Excel"""
    if len(new_poc_df) == 0:
        print("⚠️  无新POC数据，无需保存")
        return

    # 保存Excel（index=False 不保留行索引）
    new_poc_df.to_excel(output_path, index=False, engine="openpyxl")
    print(f"✅ 新POC数据已保存到：{output_path}")


# ====================== 主执行函数（按步骤串联所有操作） ======================
def main():
    try:
        print("=" * 60)
        print("📊 开始数据处理...")
        print("=" * 60)

        # 步骤1：处理漏洞扫描逻辑表
        logic_df = process_logic_file(FILE_LOGIC)

        # 步骤2：处理POC表，获取字典列表和名称集合
        poc_dict_list, poc_name_set = process_poc_file(FILE_POC)

        # 步骤3：筛选新POC
        new_poc_df, new_poc_list = filter_new_poc(logic_df, poc_name_set)

        # 步骤4：保存结果
        save_new_poc(new_poc_df, OUTPUT_FILE)

        print("\n" + "=" * 60)
        print("🎉 所有操作完成！")
        print(f"📋 关键统计：")
        print(f"   - 漏洞扫描逻辑表总数据：{len(logic_df)} 条")
        print(f"   - POC有误报路径表总数据：{len(poc_dict_list)} 条")
        print(f"   - 筛选出的新POC数据：{len(new_poc_list)} 条")
        print(f"   - 新POC保存路径：{OUTPUT_FILE}")
        print("=" * 60)

        # 返回关键结果（供调试查看）
        return {
            "poc_dict_list": poc_dict_list,  # POC表的字典列表
            "new_poc_list": new_poc_list  # 新POC的字典列表
        }

    except Exception as e:
        print(f"\n❌ 数据处理失败：{str(e)}")
        return None


# 执行主函数
if __name__ == "__main__":
    result = main()