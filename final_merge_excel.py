import pandas as pd
import os
import glob
from pathlib import Path

def merge_excel_files(input_folder: str, output_file: str = "merged_output.xlsx") -> None:
    """
    合并文件夹下所有 Excel 文件，只保留一次表头。

    Parameters:
        input_folder (str): 包含 Excel 文件的文件夹路径
        output_file (str): 输出合并后的 Excel 文件名（默认 merged_output.xlsx）
    """
    # 检查输入文件夹是否存在
    if not os.path.isdir(input_folder):
        raise NotADirectoryError(f"文件夹不存在: {input_folder}")

    # 支持 xlsx 和 xls 格式
    excel_patterns = ["*.xlsx", "*.xls"]
    excel_files = []
    for pattern in excel_patterns:
        excel_files.extend(glob.glob(os.path.join(input_folder, pattern)))

    if not excel_files:
        print("未找到任何 Excel 文件（.xlsx 或 .xls）")
        return

    print(f"找到 {len(excel_files)} 个 Excel 文件:")
    for f in excel_files:
        print(f"  - {os.path.basename(f)}")

    # 用于存储所有数据的列表
    dataframes = []

    for idx, file_path in enumerate(excel_files):
        try:
            # 读取 Excel 文件，第一行作为列名
            if file_path.endswith('.xlsx'):
                df = pd.read_excel(file_path, engine='openpyxl')
            else:  # .xls
                df = pd.read_excel(file_path, engine='xlrd')

            if df.empty:
                print(f"警告: {file_path} 为空，跳过")
                continue

            # 如果是第一个文件，保留表头；否则只取数据行（去掉表头）
            if idx == 0:
                dataframes.append(df)
                print(f"已加载第一个文件（保留表头）: {os.path.basename(file_path)}")
            else:
                # 确保列结构与第一个文件一致（按列名对齐，不同则填充 NaN）
                if not df.columns.equals(dataframes[0].columns):
                    print(f"警告: {file_path} 的列名与第一个文件不一致，将按列名对齐并填充缺失值为 NaN")
                    # 按第一个文件的列名重新索引
                    df = df.reindex(columns=dataframes[0].columns)
                dataframes.append(df)
                print(f"已追加数据: {os.path.basename(file_path)}")

        except Exception as e:
            print(f"读取文件 {file_path} 出错: {e}，跳过该文件")

    if not dataframes:
        print("没有有效数据可合并。")
        return

    # 合并所有 DataFrame
    merged_df = pd.concat(dataframes, ignore_index=True)

    # 确保输出目录存在（如果输出文件包含路径）
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 保存到新 Excel 文件
    try:
        merged_df.to_excel(output_file, index=False, engine='openpyxl')
        print(f"\n合并完成！共 {len(merged_df)} 行数据（包含表头行）。")
        print(f"输出文件: {os.path.abspath(output_file)}")
    except Exception as e:
        print(f"保存文件时出错: {e}")

if __name__ == "__main__":
    # ---------- 使用示例 ----------
    # 方式1: 直接修改变量
    folder_path = "./poc_notra_invalid"          # 当前文件夹，可改为其他路径如 "./data"
    output_path = "{}/merged_output.xlsx".format(folder_path)

    # 方式2: 通过命令行参数（可选，取消注释即可使用）
    # import argparse
    # parser = argparse.ArgumentParser(description="合并文件夹下所有 Excel 文件")
    # parser.add_argument("folder", nargs="?", default=".", help="包含 Excel 文件的文件夹路径（默认当前目录）")
    # parser.add_argument("-o", "--output", default="merged_output.xlsx", help="输出文件路径（默认 merged_output.xlsx）")
    # args = parser.parse_args()
    # folder_path = args.folder
    # output_path = args.output

    merge_excel_files(folder_path, output_path)