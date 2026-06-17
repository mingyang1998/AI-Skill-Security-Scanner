(base) PS D:\AI安全产品\ai-skill-security-scanner> python run.py
2026-05-28 10:19:04,447 [INFO] app: ============================================================
2026-05-28 10:19:04,450 [INFO] app: SkillGuard - AI Skill Security Scanner 已
启动
2026-05-28 10:19:04,450 [INFO] app: 访问地址: http://localhost:5000
2026-05-28 10:19:04,450 [INFO] app: 日志文件: D:\AI安全产品\ai-skill-security-scanner\data\logs\app.log
2026-05-28 10:19:04,450 [INFO] app: ============================================================
 * Serving Flask app 'app'
 * Debug mode: on
2026-05-28 10:20:29,470 [INFO] app.routes: [任务启动] skill=SKILL_朱雀实验室, task_id=585800fb-fdc6-41ee-967e-84f29d63d7f9
2026-05-28 10:20:29,472 [INFO] app.routes: [任务启动] 加载 16 条活跃检测规则
2026-05-28 10:20:29,472 [INFO] app.scanner.engine: [扫描开始] skill=SKILL_朱 
雀实验室, path=D:\AI安全产品\ai-skill-security-scanner\data\uploads\585800fb-fdc6-41ee-967e-84f29d63d7f9\SKILL.md, options={'static_analysis': True, 'signature_matching': True, 'llm_analysis': True, 'sandbox': True, 'llm_static_review': True, 'llm_correlation': True}
2026-05-28 10:20:29,472 [INFO] app.scanner.engine: [阶段1] 单文件扫描: D:\AI 
安全产品\ai-skill-security-scanner\data\uploads\585800fb-fdc6-41ee-967e-84f29d63d7f9\SKILL.md
2026-05-28 10:20:29,472 [INFO] app.scanner.engine: [单文件分析] file=D:\AI安 
全产品\ai-skill-security-scanner\data\uploads\585800fb-fdc6-41ee-967e-84f29d63d7f9\SKILL.md, options={'static_analysis': True, 'signature_matching': True, 'llm_analysis': True, 'sandbox': True, 'llm_static_review': True, 'llm_correlation': True}
2026-05-28 10:20:29,477 [INFO] app.scanner.engine: [单文件分析] 文件读取完成, 行数=358, 字符数=14924
2026-05-28 10:20:29,517 [INFO] app.scanner.engine: [LLM意图分析-单文件] file=D:\AI安全产品\ai-skill-security-scanner\data\uploads\585800fb-fdc6-41ee-967e-84f29d63d7f9\SKILL.md, 内容长度=14924, 分块数=6
2026-05-28 10:21:22,997 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=985, completion=1783, total=2768
2026-05-28 10:22:19,671 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=1015, completion=1845, total=2860
2026-05-28 10:22:58,193 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=630, completion=1247, total=1877
2026-05-28 10:23:40,454 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=904, completion=1334, total=2238
2026-05-28 10:24:24,983 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=1261, completion=1398, total=2659
2026-05-28 10:25:02,420 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=863, completion=1284, total=2147
2026-05-28 10:25:02,433 [INFO] app.scanner.engine: [L2 LLM静态审查] 开始审查 
1 个候选片段
2026-05-28 10:25:53,178 [INFO] app.scanner.engine: [LLM调用] token用量: prompt=413, completion=1586, total=1999
2026-05-28 10:25:53,183 [INFO] app.scanner.engine: LLM 判定误报: D:\AI安全产
品\ai-skill-security-scanner\data\uploads\585800fb-fdc6-41ee-967e-84f29d63d7f9\SKILL.md L186 - 匹配内容位于Markdown文档文件(SKILL.md)中，属于安全审计规则 
说明或AI扫描器提示词的描述性文本，而非可执行代码。该行仅为列举审计时需要关注 
的安全行为特征，正则规则因直接匹配到'bypa
2026-05-28 10:25:53,183 [INFO] app.scanner.engine: L2 LLM 静态审查: 1/1 个候 
选片段已审查
2026-05-28 10:25:53,183 [INFO] app.scanner.engine: [L3 LLM关联分析] 确认发现 
数=0<2，跳过关联分析
2026-05-28 10:25:53,189 [INFO] app.routes: [进度更新] task_id=585800fb-fdc6-41ee-967e-84f29d63d7f9, progress=100%
2026-05-28 10:25:53,189 [INFO] app.scanner.engine: [扫描完成] risk_level=warning, risk_score=5, findings=1, files=1, llm_calls=7, llm_failures=0
2026-05-28 10:25:53,210 [INFO] app.routes: [任务完成] skill=SKILL_朱雀实验室, risk_level=warning, risk_score=5, findings=1, files=1
(base) PS D:\AI安全产品\ai-skill-security-scanner> 