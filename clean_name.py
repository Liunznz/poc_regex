import pandas as pd
import re

# 读取 Excel 文件
input_file = "poc_final_fscan_nuclei.xlsx"
df = pd.read_excel(input_file, sheet_name="Sheet1")


def clean_component_only(text):
    """只处理组件名称部分，删除特殊字符并转小写，漏洞类型部分保持不变"""
    if not isinstance(text, str):
        return text

    # 查找第一个空格的位置
    first_space = text.find(' ')

    if first_space == -1:
        # 没有空格，整个字符串作为组件名处理
        cleaned = re.sub(r'[^\w\s\u4e00-\u9fff]', ' ', text)
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned.lower().strip()
    else:
        # 分离组件名和漏洞类型
        component = text[:first_space]
        vuln_type = text[first_space:]  # 漏洞类型保持不变

        # 只处理组件名：删除特殊字符，转小写
        component_cleaned = re.sub(r'[^\w\s\u4e00-\u9fff]', ' ', component)
        component_cleaned = re.sub(r'\s+', ' ', component_cleaned)
        component_cleaned = component_cleaned.lower().strip()

        # 漏洞类型原样保留
        return component_cleaned + vuln_type


# 处理第一列（漏洞中文名称(新)）
df.iloc[:, 0] = df.iloc[:, 0].apply(clean_component_only)

# 保存为新文件
output_file = "poc_final_fscan_nuclei_cleaned.xlsx"
df.to_excel(output_file, index=False, sheet_name="Sheet1")
print(f"处理完成，已保存至：{output_file}")