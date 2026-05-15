# poc_regex
 poc_regex：从xray/fscan/nuclei的 全部YAML 文件中提取 GET 的payload特征路径，生成高质量正则规则

├── nuclei_poc_analysis.py               # 主解析脚本：递归遍历 YAML 文件，提取 GET 路径，生成原始 Excel

├── poc_name_chV2.py                     # 中英文翻译 + 二次无效路径过滤 + 去重合并，输出最终清洗版

├── re_generate.py                       # 从「所有路径(原始)」列重新生成正则（支持手动编辑后重算）

├── wubao_all_type.py                    # 正则误报风险评估：按漏洞类型匹配攻击特征，输出高风险规则报告

├── final_merge_excel.py                 # 合并多个 Excel 文件（支持 .xlsx / .xls）

├── 2re_match_result.py                  # 早期版本：正则验证脚本（调用 API 校验）已注释部分，保留参考

├── 3path_submit201.py                   # 提交成功规则到服务端（并发 + 全局去重）

├── 4_0final_poc_nuclei_fscan.py         # 最终合并清洗脚本：整合 poc_luru / fscan_poc 等多源数据

├── 4excelfile_poc_match.py              # 对比「漏洞扫描逻辑表」与「POC表」，筛选出新增 POC

├── 5parse_vuln.py                       # 解析 vuln_names.txt，提取组件、漏洞类型、CVE 编号

├── clean_name.py                        # 清洗漏洞中文名称（删除特殊字符、转小写）

├── re_quchong.py                        # 在 Excel 中标记重复行（红色字体或红色背景）

├── wubao.py                             # 早期命令执行规则风险评估（已整合到 wubao_all_type，保留参考）

├── poc_name_ch.py                       # 早期版本：漏洞名称翻译（保留参考）

├── invalid_path.txt                     # 无效路径黑名单（300+ 条，可自由增删）

├── vuln_names.txt                       # 漏洞名称原始数据（用于测试 5parse_vuln.py）

├── $dirname_instruction.txt             # 目录结构说明文档（解释各文件夹用途）

├── poc_final_fscan_nuclei_cleanedV5.xlsx   # 最终产出的 707 条正则规则（直接可用）

└── README.md                            # 项目说明文档


本项目提供一套完整的 Python 脚本，用于：

- 递归解析 xray、fscan、nuclei 等漏洞扫描器的 YAML 模板文件。
- 提取所有 GET 请求的路径（`path` 字段 + `raw` 第一行）。
- 清洗无效路径（如 `/admin/`、`/index.html`），支持自定义黑名单。
- 自动生成标准化的正则表达式：`.*?(?:path1|path2|...).*`
- 按漏洞类型（SQL注入、XSS、RCE 等）分类排序，输出 Excel。
- 对已有正则进行“误报风险评分”，找出缺少攻击特征的宽泛规则。

**输出示例（Excel）：**

| 组件 | 漏洞类型 | 漏洞编号 | 漏洞中文名称 | 正则字符串(直接复制) | 所有路径(原始) |
|------|----------|----------|--------------|----------------------|----------------|
| Joomla | SQL注入 | CVE-2018-6605 | Joomla_SQL注入 | .*?(?:/index.php?option=com_zhbaidumap...).* | /index.php?option=com_zhbaidumap... |

> 当前已处理 **707 条**可直接用于 WAF/IDS 的正则规则。如下图
<img width="1920" height="1019" alt="image" src="https://github.com/user-attachments/assets/46778682-ef1f-4ccb-b038-eabec2eba8b7" />

---

## 快速开始

### 1. 环境要求
- Python 3.8+
- 安装依赖：
  pip install pandas openpyxl pyyaml tqdm

### 2. 使用场景
WAF 规则库建设 – 将 Excel 中的“正则字符串(直接复制)”批量导入 WAF，实现基于路径的精确拦截。
Nginx 安全配置 – 在 location 或 if 块中使用正则匹配恶意请求。
日常安全运营 – 定期扫描最新的 nuclei 模板，自动生成补充规则，持续更新。
内部红队检测 – 用自己的 POC 生成正则，快速验证设备覆盖率。

### 3.注意事项
当前版本仅处理 GET 请求的路径（包括 path 和 raw 第一行）。POST 请求的 body 和响应匹配暂不支持。
无效路径黑名单 invalid_path.txt 基于常见管理路径和测试路径整理，请根据自身业务增删。
生成的正则默认是 .*?(?:...).* 形式，可直接用于大多数支持 Perl 兼容正则的引擎（如 PCRE）。
建议在上线前通过灰度规则或测试流量验证。
## 4、贡献与反馈

欢迎提交 PR 或 Issue。如果你有更好的清洗思路或额外的漏洞类型特征，欢迎分享。

**关注我的公众号：[Liunz网络安全剖析] 获取更多安全自动化干货。**  
<img width="430" height="430" alt="网络安全剖析" src="https://github.com/user-attachments/assets/de170457-7ed4-4356-a2b8-1ae0e1c79988" />

