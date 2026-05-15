import re
import pandas as pd

# ----------------------------- 中文映射表（可扩展）-----------------------------
NAME_MAP = {
    'yongyou': '用友', 'yonyou': '用友', 'zhixiang': '致翔', 'fanwei': '泛微',
    'tongda': '通达OA', 'seeyon': '致远OA', 'landray': '蓝凌', 'wanhu': '万户',
    'weaver': '泛微', 'ufida': '用友', 'finereport': '帆软', 'metinfo': '米拓',
    'dedecms': '织梦', 'wordpress': 'WordPress', 'joomla': 'Joomla','ruijie':'锐捷','ruoyi':'若依',
    'magento': 'Magento', 'woocommerce': 'WooCommerce', 'discuz': 'Discuz!','Sangfor':'深信服',
    'phpok': 'PHPOK', 'phpshe': 'PHPSHE', 'qax': '奇安信', 'realor': '瑞友',
    'seacms': '海洋CMS', 'tpshop': 'TPShop', 'weiphp': '微擎', 'wuzhicms': '五指CMS',
    'zcms': 'ZCMS', 'aerocms': 'AeroCMS', 'amss': 'AMSS', 'changjet': '畅捷',
    'cmseasy': 'CMSEasy', 'dahua': '大华', 'dotnetcms': 'DotNetCMS',"duomi":"多米CMS",
    'duomicms': '多米CMS', 'ectouch': 'ECTouch', 'hjsoft': '宏景软件',
    'hongjing': '宏景', 'jsoa': 'JSOA', 'mallbuilder': 'Mallbuilder商城', 'sitemap': '站点地图',
    'apache': 'Apache', 'nginx': 'Nginx', 'iis': 'IIS', 'tomcat': 'Tomcat',
    'weblogic': 'WebLogic', 'jboss': 'JBoss', 'glassfish': 'GlassFish',
    'resin': 'Resin', 'jetty': 'Jetty', 'struts': 'Struts', 'spring': 'Spring',
    'thinkphp': 'ThinkPHP', 'laravel': 'Laravel', 'rails': 'Rails',
    'django': 'Django', 'flask': 'Flask', 'ecshop': 'ECShop',
    'phpcms': 'PHPCMS', 'dede': '织梦', 'empirecms': '帝国CMS',
    '74cms': '74CMS', 'finecms': 'FineCMS', '齐博': '齐博CMS', '齐博cms': '齐博CMS',
    '海洋cms': '海洋CMS', '苹果cms': '苹果CMS', '云购cms': '云购CMS',
    '致远oa': '致远OA', '泛微oa': '泛微OA', '通达oa': '通达OA', '万户oa': '万户OA',
    '用友': '用友', '金蝶': '金蝶', '蓝凌': '蓝凌', '红帆': '红帆', '汇高': '汇高',
    '启莱': '启莱', '智邦': '智邦', '致翔': '致翔', '大汉': '大汉', '大华': '大华',
    '海康威视': '海康威视', '深信服': '深信服', '天融信': '天融信', '网康': '网康',
    '绿盟': '绿盟', '迈普': '迈普', '锐捷': '锐捷', '思科': '思科', '华为': '华为',
    'vmware': 'VMware', 'citrix': 'Citrix', 'apache': 'Apache', 'nginx': 'Nginx',
    'iis': 'IIS', 'tomcat': 'Tomcat', 'weblogic': 'WebLogic', 'jboss': 'JBoss',
    'glassfish': 'GlassFish', 'resin': 'Resin', 'jetty': 'Jetty', 'struts': 'Struts',
    'spring': 'Spring', 'thinkphp': 'ThinkPHP', 'laravel': 'Laravel', 'rails': 'Rails',
    'django': 'Django', 'flask': 'Flask', 'ecshop': 'ECShop',
    'phpcms': 'PHPcms', 'dede': '织梦', 'empirecms': '帝国CMS', '74cms': '74CMS',
    'finecms': 'FineCMS', '齐博': '齐博CMS', '齐博cms': '齐博CMS', '海洋cms': '海洋CMS',
    '苹果cms': '苹果CMS', '云购cms': '云购CMS',"yungoucms":"云购CMS", '致远oa': '致远OA', '泛微oa': '泛微OA',
    '通达oa': '通达OA', '万户oa': '万户OA', '用友': '用友', '金蝶': '金蝶', '蓝凌': '蓝凌',
    '红帆': '红帆', '汇高': '汇高', '启莱': '启莱', '智邦': '智邦', '致翔': '致翔',
    '大汉': '大汉', '大华': '大华', '海康威视': '海康威视', '深信服': '深信服',
    '天融信': '天融信', '网康': '网康', '绿盟': '绿盟', '迈普': '迈普', '锐捷': '锐捷',
    '思科': '思科', '华为': '华为', 'vmware': 'VMware', 'citrix': 'Citrix',
    'apache': 'Apache', 'nginx': 'Nginx', 'iis': 'IIS', 'tomcat': 'Tomcat',
    'weblogic': 'WebLogic', 'jboss': 'JBoss', 'glassfish': 'GlassFish', 'resin': 'Resin',
    'jetty': 'Jetty', 'struts': 'Struts', 'spring': 'Spring', 'thinkphp': 'ThinkPHP',
    "ecology":"泛微 e-cology OA","e Office":"","doccms":"DocCMS","fangwei":"方维CMS",
    'laravel': 'Laravel', 'rails': 'Rails', 'django': 'Django', 'flask': 'Flask','aikcms':"AikCMS"
}

# 常见漏洞类型（按优先级匹配）
VULN_TYPES = [
    'SQL注入', '跨站脚本', '任意文件上传', '任意文件读取', '任意文件下载',
    '任意文件包含', '远程代码执行', '远程命令执行', '信息泄露', '服务端请求伪造',
    'CRLF注入', 'XML外部实体注入', '路径遍历', '目录遍历', '命令注入', '代码注入',
    '开放重定向', '认证绕过', '授权绕过', '权限提升', '文件泄露', '配置信息泄露',
    '未授权访问', '越权访问', '反序列化', '模板注入', '表达式注入', 'SSRF', 'XXE',
    'XSS', 'CSRF', 'LFI', 'RFI', 'RCE', 'SQLi'
]

# 通用/无意义词列表（仅用于标记“是否组件”，不删除数据）
GENERIC_WORDS = [
    'xss', 'crlf', 'unauthenticated', 'vulnerability', 'pre', 'privid', 'run id',
    'sms page', 'v commond id参数', 'v plusajax officebuilding', 'wap company show',
    'weixin', 'error', 'id', 'in', 'ms', 'reflected', 'reflective', 'setpreferences',
    'sick', 'verificação', 'wordfence', 'acme', 'adobe', 'aem', 'bitrix',
    'blackboard', 'btoptionscom', 'chamilo', 'concrete', 'dedecms', 'discourse',
    'eclipse', 'empirecms', 'httpbin', 'javamelody', 'kafdrop', 'laravel', 'lucee',
    'microweber', 'moodle', 'nscript', 'oracle', 'php', 'qcubed', 'rails', 'sap',
    'siteminder', 'squirrelmail', 'swagger', 'turbocrm', 'vmware', 'wems', 'ansible',
    'apache', 'phpstan', 'pyproject', 'symfony', 'vscode', 'aem QueryBuilder JsonServlet',
    'aem Secrets', 'apache Davical', 'bsphp', 'caucho Resin', 'drupal模块xmlsitemap',
    'fckeditor', 'glpi遥测', 'golang语言pprof', 'go信息', 'go语言pprof', 'iceflow VPN',
    'joomla com booking', 'joomla版本', 'kubernetes Kustomization', 'landray EIS WS',
    'magento', 'magento缓存', 'milesight', 'nginx', 'phpmyadmin', 'php信息', 'php源码',
    'ruijie RG', 'seeyon OA A config', 'seeyon OA A createMysql', 'seeyon OA A initDataAssess',
    'weaver e', 'wordpress系统cve', '大华设备', '锐捷路由webgl', '时空智友', 'adobe',
    'argo', 'caucho', 'fanruan', 'huaxia', 'jetty', 'apache环境', 'bitrix全路径',
    'cobubrazor', 'composer', 'coremail', 'elmah', 'github工作流', 'git配置', 'git日志',
    'glpi状态', 'kubernetes etcd', 'oracle EBS SQL', 'oracle EBS凭据', 'putty', 'roundcube',
    'ruby on Rails', 'sftp', 'vbulletin', 'woodwing Studio', 'wpeprivate', '谷歌服务',
    'wordpress Modern Events', 'wordpress 社交指标', 'apache环境php环境变量',
    'apache 服务端请求伪造', 'discuz 服务端请求伪造', 'ibm 服务端请求伪造',
    'jboss 服务端请求伪造', 'jira 服务端请求伪造', 'jira系统cve', 'microstrategy 服务端请求伪造',
    'openfire系统cve', 'parameter 服务端请求伪造', 'websphere 服务端请求伪造',
    'wordpress 服务端请求伪造', 'wso 服务端请求伪造', 'amazon EC', 'anheng 服务端请求伪造',
    'apache 服务端请求伪造', 'atlassian Confluence', 'discuz DownRemoteImg', 'fanruan 服务端请求伪造',
    'microstrategy tinyurl', 'office Web Apps Server', 'podcastgenerator', 'skype for Business',
    'splash Render', 'ueditor', 'umbraco', 'weaver e 服务端请求伪造', 'web Page Test',
    'websphere pre', 'wso 服务端请求伪造', 'yongyou 服务端请求伪造', 'zimbra 协作套件',
    '安恒明御', 'cacti Weathermap', 'detector', 'global', 'groupoffice',
    'linux', 'pmb', 'seeyon', 'tpshop', 'apache HTTPD系统CVE', 'ecoa', 'flyrise',
    'javo', 'jinfornet', 'joomla com fabrik', 'karel', 'kingdee EAS', 'liveobs',
    'management', 'pacsone', 'selea', 'softneta', 'tpshop系统', 'voyager', 'wordpress Javo',
    '帆软finereport系统', '泛微ecology系统spring', '泛微oa E Cology', '金蝶eas', '金蝶oa',
    '微擎系统', 'custom', 'finereport', 'next', 'nuxt', 'oracle', 'sap', 'solr', 'weiphp',
    'wooyun', 'wordpress', 'yishaadmin', 'caddy', 'checker', 'dedecms', 'homeautomation',
    'http', 'keycloak', 'next', 'open', 'sap', 'apache 文件泄露', 'application', 'azure',
    'blazor', 'config', 'credentials', 'environment', 'froxlor', 'joomla', 'nuget',
    'phpunit', 'platformio', 'pnpm', 'production', 'proftpd', 'qihang', 'ruby', 'service',
    'sftp', 'snyk', 'sound', 'styleci', 'symfony', 'wadl', 'yarn', 'github身份认证',
    'appcms', 'bt742', 'citrix系统cve', 'discuz 微信', 'etcd', 'phpmyadmin', 'springboot',
    'swagger UI', '金和oa', '启智', '通达oa会议', '致远oa AJAX', 'aem Package', 'kentico',
    'thinvnc', 'viewlinc', 'bitrix 内容欺骗', 'sonicwall', 'solr系统', 'active Directory',
    'apache Axis', 'citrix XenMobile', 'confluence系统cve', 'gilacms', 'gocd', 'jboss系统cve',
    'jenkins系统cve', 'jira系统cve', 'kibana系统cve', 'nagios系统cve', 'next js', 'php CGI',
    'phpcms系统cve', 'pulse系统cve', 'rconfig系统cve', 'springboot系统cve', 'youphptube Encoder'
]

def normalize_component(comp):
    """规范化组件名：转中文、OA大写、去多余空格"""
    if not comp:
        return ''
    comp_lower = comp.lower()
    for eng, chi in NAME_MAP.items():
        if eng in comp_lower:
            comp = chi
            break
    comp = re.sub(r'\bOa\b', 'OA', comp, flags=re.IGNORECASE)
    comp = ' '.join(comp.split())
    return comp

def extract_cve(text):
    """提取CVE编号"""
    match = re.search(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    match = re.search(r'(?i)cve[\s-]*(\d{4})[\s-]*(\d+)', text)
    if match:
        return f"CVE-{match.group(1)}-{match.group(2)}"
    return ''

def extract_vuln_type(text):
    """提取漏洞类型"""
    text_clean = text.replace('-', '').replace(' ', '')
    for vt in VULN_TYPES:
        vt_clean = vt.replace('-', '').replace(' ', '')
        if vt_clean in text_clean:
            return vt
        if vt in text:
            return vt
    return ''

def is_component_valid(comp, vuln):
    """判断是否为有效组件（仅用于标记，不删除数据）"""
    if not comp or not vuln:
        return False
    comp_lower = comp.lower()
    for word in GENERIC_WORDS:
        if word in comp_lower:
            return False
    return True

def parse_line(line):
    """解析一行，返回组件名、漏洞类型、CVE、是否组件"""
    line_orig = line.strip()
    if not line_orig:
        return '', '', '', False
    # 提取CVE
    cve = extract_cve(line_orig)
    line_temp = line_orig
    if cve:
        line_temp = re.sub(r'(?i)CVE[-\s]*\d{4}[-\s]*\d+', '', line_temp).strip()
    # 提取漏洞类型
    vuln = extract_vuln_type(line_temp)
    if vuln:
        line_temp = line_temp.replace(vuln, '').strip()
    # 剩余部分为组件名
    component = line_temp.strip()
    if component:
        component = normalize_component(component)
    # 如果组件名为空，尝试用整个原始行作为组件名
    if not component:
        component = normalize_component(line_orig)
    # 判断是否有效组件
    is_valid = is_component_valid(component, vuln)
    return component, vuln, cve, is_valid

def main(input_file='vuln_names.txt', output_file='vuln_analysis.xlsx'):
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    data = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        comp, vuln, cve, is_valid = parse_line(line)
        # 如果漏洞类型为空，标记为“未知”
        if not vuln:
            vuln = '未知'
        # 构建漏洞中文名称
        if comp and vuln:
            name = f"{comp}_{vuln}"
            if cve:
                name += f"_{cve}"
        else:
            name = line  # 保底用原始行
        data.append([line, comp, vuln, cve, name, is_valid])
    df = pd.DataFrame(data, columns=['原始行', '组件', '漏洞类型', '漏洞编号', '漏洞中文名称', '是否组件'])
    df.to_excel(output_file, index=False)
    print(f"处理完成！共 {len(data)} 条记录。")
    print(f"结果已保存至 {output_file}")

if __name__ == '__main__':
    # 请将您的原始数据保存为 vuln_names.txt（每行一个漏洞名称），然后运行此脚本。
    main()