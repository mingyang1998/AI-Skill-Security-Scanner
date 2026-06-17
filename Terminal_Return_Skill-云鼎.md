(base) PS D:\AI安全产品\ai-skill-security-scanner> python run.py
2026-05-28 11:05:01,162 [INFO] app: ============================================================
2026-05-28 11:05:01,162 [INFO] app: SkillGuard - AI Skill Security Scanner 已
启动
2026-05-28 11:05:01,168 [INFO] app: 访问地址: http://localhost:5000
2026-05-28 11:05:01,168 [INFO] app: 日志文件: D:\AI安全产品\ai-skill-security-scanner\data\logs\app.log
2026-05-28 11:05:01,169 [INFO] app: ============================================================
 * Serving Flask app 'app'
 * Debug mode: on
2026-05-28 11:06:03,985 [INFO] app.routes: [任务启动] skill=SKILL_云鼎实验室, task_id=ed23634e-7ecf-4f0f-adb6-351447802e5a
2026-05-28 11:06:04,005 [INFO] app.routes: [任务启动] 加载 16 条活跃检测规则
2026-05-28 11:06:04,010 [INFO] app.scanner.engine: [扫描开始] skill=SKILL_云 
鼎实验室, path=D:\AI安全产品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md, options={'static_analysis': True, 'signature_matching': True, 'llm_analysis': True, 'sandbox': True, 'llm_static_review': True, 'llm_correlation': True}
2026-05-28 11:06:04,015 [INFO] app.scanner.engine: [阶段1] 单文件扫描: D:\AI 
安全产品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md
2026-05-28 11:06:04,018 [INFO] app.scanner.engine: [单文件分析] file=D:\AI安
全产品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md, options={'static_analysis': True, 'signature_matching': True, 'llm_analysis': True, 'sandbox': True, 'llm_static_review': True, 'llm_correlation': True}
2026-05-28 11:06:04,027 [INFO] app.scanner.engine: [单文件分析] 文件读取完成, 行数=413, 字符数=13891
2026-05-28 11:06:04,099 [INFO] app.scanner.engine: [LLM意图分析-单文件] file=D:\AI安全产品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md, 内容长度=13891, 分块数=6
2026-05-28 11:06:44,507 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=1156, completion=1549, total=2705
2026-05-28 11:07:20,267 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=1368, completion=1382, total=2750
2026-05-28 11:07:56,295 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=1228, completion=1357, total=2585
2026-05-28 11:08:29,051 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=1373, completion=1271, total=2644
2026-05-28 11:09:03,549 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=1882, completion=1381, total=3263
2026-05-28 11:09:36,890 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=804, completion=1315, total=2119
2026-05-28 11:09:36,919 [INFO] app.scanner.engine: [L2 LLM静态审查] 开始审查 
23 个候选片段
2026-05-28 11:10:13,725 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=571, completion=1566, total=2137
2026-05-28 11:10:13,732 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L107 - 匹配内容位于Markdown文档文件(SKILL.md)中，属于安全审计规则 
或AI技能定义的说明性文本。该行仅为列举常见的网络请求工具与库名称，用于指导安 
全扫描或特征检测，并非实际执行网络请求或数据外
2026-05-28 11:10:50,921 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=555, completion=1529, total=2084
2026-05-28 11:10:50,927 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L113 - 该文件为Markdown文档（SKILL.md），内容是在定义安全扫描器或AI技能的检测规则与关键词分类。匹配行位于“权限提升类”标题下，仅作为规则说明列举
了需要监控的敏感命令关键字（sudo、chm
2026-05-28 11:11:20,435 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=522, completion=1232, total=1754
2026-05-28 11:11:20,442 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L149 - 匹配内容位于Markdown文档文件(SKILL.md)的表格中，仅为安全审 
计规则说明与示例对比（解释sudo、chmod 777等命令的合理与恶意使用场景），并非可
执行代码或实际脚本逻辑。正则规则误
2026-05-28 11:11:49,347 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=526, completion=1277, total=1803
2026-05-28 11:11:49,352 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L149 - 匹配内容位于Markdown文档(SKILL.md)的表格中，属于安全审计指 
南的说明性文本/文档示例，仅用于解释权限提升的判定标准及合理与恶意用法的区别。
该文件不包含任何可执行代码或实际运行的命令。正
2026-05-28 11:12:19,070 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=534, completion=1275, total=1809
2026-05-28 11:12:19,078 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L149 - 匹配内容位于Markdown文档文件(SKILL.md)的表格中，属于安全审 
计指南或技能说明文档。该行仅是在概念层面解释“权限提升”的判定标准，并举例说明sudo、chmod等命令的合理与恶意使用场景
2026-05-28 11:12:50,098 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=541, completion=1306, total=1847
2026-05-28 11:12:50,105 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L149 - 匹配内容位于Markdown文档（.md）中，是安全审计指南或AI提示词
文档中的说明性表格行。该文本仅用于教学和规则定义，旨在指导如何区分sudo、chmod等命令的合理使用与恶意滥用场景，并非可执行
2026-05-28 11:13:24,125 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=623, completion=1444, total=2067
2026-05-28 11:13:24,132 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L188 - 匹配内容位于Markdown文档文件(SKILL.md)中，属于安全扫描规则 
的设计说明与检测模式示例，并非实际可执行代码或运行指令。正则规则错误地将描述 
威胁特征的文档文本标记为真实的权限提升操作，属于
2026-05-28 11:13:53,888 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=647, completion=1324, total=1971
2026-05-28 11:13:53,892 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L264 - 匹配内容位于Markdown文档文件(SKILL.md)中，属于安全扫描规则 
的定义说明与分类指南，而非实际可执行代码。该段落仅用于描述安全审计逻辑（如何 
判定权限提升配合危险操作的威胁等级及降级条件），
2026-05-28 11:14:27,455 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=652, completion=1402, total=2054
2026-05-28 11:14:27,461 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L264 - 匹配内容位于Markdown文档（SKILL.md）中，属于安全扫描规则与 
威胁定级指南的说明文本。其中的sudo、chmod 777、curl | bash等关键词仅作为分类 
标准的示例引用，用于描述何
2026-05-28 11:15:01,840 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=654, completion=1445, total=2099
2026-05-28 11:15:01,844 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L264 - 匹配内容位于SKILL.md文档中，属于安全扫描器自身的规则定义与 
说明文本。该行仅以示例形式描述何种命令组合应被判定为权限提升威胁，并非实际可 
执行代码或脚本。正则规则因单纯匹配到文档中的sudo、ch
2026-05-28 11:15:40,026 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=652, completion=1598, total=2250
2026-05-28 11:15:40,032 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L264 - 该文件为Markdown文档（SKILL.md），从路径和上下文可知其为AI 
安全扫描器自身的规则定义与判定指南，而非可执行代码。匹配行仅是在文档中描述安 
全审计规则，举例说明何种命令组合应被归类为恶意权
2026-05-28 11:16:13,897 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=577, completion=1396, total=1973
2026-05-28 11:16:13,903 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L129 - 匹配内容位于Markdown文档(SKILL.md)中，属于安全审计指南/检查
清单的描述性文本。该行仅作为示例列举了代码审计时需要重点监控的危险删除命令与 
函数API，并非实际可执行代码。正则规则误将文
2026-05-28 11:16:49,802 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=588, completion=1376, total=1964
2026-05-28 11:16:49,806 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L129 - 匹配内容位于Markdown文档文件(SKILL.md)中，是安全审计操作指 
南/提示词中的命令示例列举，用于说明审计过程中需要重点监控的文件操作类型，并非
实际可执行代码。正则规则仅基于关键字进行静态匹
2026-05-28 11:17:24,040 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=522, completion=1374, total=1896
2026-05-28 11:17:24,046 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L148 - 该匹配项位于Markdown文档文件（SKILL.md）中，属于安全知识库 
或审计指南的说明性表格。`rm -rf /` 仅作为“系统破坏”类别的描述性示例出现，并非
可执行代码或实际运行脚本。正则规则因
2026-05-28 11:17:57,089 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=541, completion=1369, total=1910
2026-05-28 11:17:57,099 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L149 - 该匹配内容位于Markdown文档文件(SKILL.md)中，是用于说明安全 
审计规则的示例表格。文本明确将sudo rm -rf /作为恶意行为的反面教材进行对比教学
，并非实际可执行代码或脚本。正则引
2026-05-28 11:18:40,051 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=623, completion=1758, total=2381
2026-05-28 11:18:40,056 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L258 - 匹配内容位于Markdown文档文件(SKILL.md)中，该文件用于定义AI 
技能安全扫描器的审计规则与分级标准。证据行仅为描述性文本，说明检测逻辑与判定 
条件，并非实际可执行代码。正则规则误将文档中的
2026-05-28 11:19:12,020 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=658, completion=1321, total=1979
2026-05-28 11:19:12,030 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L259 - 匹配内容位于Markdown文档（SKILL.md）中，属于安全审计规则的 
定义说明。其中的rm -rf命令仅为文档中的策略示例文本，用于阐述审计降级条件，并 
非实际可执行代码。正则规则误将文档示例识别为
2026-05-28 11:19:45,267 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=657, completion=1365, total=2022
2026-05-28 11:19:45,267 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L259 - 该匹配内容位于Markdown文档文件（SKILL.md）中，属于安全审计 
规则说明文档。其中的rm -rf命令仅作为规则降级条件的文本示例出现，并非实际可执 
行代码。正则规则误将文档中的示例命令识别为危
2026-05-28 11:20:18,938 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=651, completion=1352, total=2003
2026-05-28 11:20:18,948 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L264 - 该匹配行位于Markdown文档文件(SKILL.md)中，属于安全审计规则 
的定义说明。其中的`sudo rm -rf /`仅作为描述性示例，用于向开发者或审计引擎解释
何种操作组合应被判定为恶意，并非
2026-05-28 11:20:49,718 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=564, completion=1267, total=1831
2026-05-28 11:20:49,724 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L94 - 匹配内容位于Markdown文档（SKILL.md）中，属于安全扫描操作指南
的说明文本。该行仅作为示例列举了审计时需要搜索的危险关键词，并非实际可执行代 
码。此处不存在任何命令执行逻辑、外部输入拼接或运
2026-05-28 11:21:18,622 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=556, completion=1186, total=1742
2026-05-28 11:21:18,627 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L95 - 匹配内容位于Markdown文档文件(SKILL.md)中，属于安全扫描流程说
明里列举的“待检测危险关键词”示例清单，并非实际可执行代码。该文本仅用于描述扫 
描规则的目标函数名，不存在任何命令拼接、参数
2026-05-28 11:21:55,294 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=565, completion=1490, total=2055
2026-05-28 11:21:55,301 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L94 - 匹配内容位于Markdown文档（SKILL.md）中，属于AI安全扫描器的操
作指南/提示词文本。该行仅为列举供扫描器检索的“命令执行类”危险关键词示例，并非
实际可执行代码，也不包含任何混淆逻辑或执行
2026-05-28 11:22:28,495 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=663, completion=1282, total=1945
2026-05-28 11:22:28,501 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\ed23634e-7ecf-4f0f-adb6-351447802e5a\SKILL.md L133 - 该片段出自Markdown格式的安全审计操作指南（SKILL.md），而非 
可执行代码。匹配行描述的是防御性检测流程，明确要求审计者在发现可疑远程下载执 
行行为时，仅使用web_fetch抓取内容进行静态
2026-05-28 11:22:28,503 [INFO] app.scanner.engine: L2 LLM 静态审查: 23/23 个 
候选片段已审查
2026-05-28 11:22:28,503 [INFO] app.scanner.engine: [L3 LLM关联分析] 确认发现 
数=0<2，跳过关联分析
2026-05-28 11:22:28,530 [INFO] app.routes: [进度更新] task_id=ed23634e-7ecf-4f0f-adb6-351447802e5a, progress=100%
2026-05-28 11:22:28,531 [INFO] app.scanner.engine: [发现去重] 23 → 12，合并了
 11 条重复发现
2026-05-28 11:22:28,532 [INFO] app.scanner.engine: [扫描完成] risk_level=high-risk, risk_score=60, findings=12, files=1, llm_calls=29, llm_failures=0     
2026-05-28 11:22:28,564 [INFO] app.routes: [任务完成] skill=SKILL_云鼎实验室, risk_level=high-risk, risk_score=60, findings=12, files=1

(base) PS D:\AI安全产品\ai-skill-security-scanner> 