# SkillGuard - AI Skill Security Scanner

## 项目简介

SkillGuard 是一款基于多维度安全分析技术的 AI Skills 安全检测平台，参考奇安信 SAFESKILL 产品设计思路开发，为 Skill 用户、开发者和安全研究人员提供专业的 AI Skill 安全验证与扫描服务。

平台采用 **L1 静态候选 → L2 LLM 静态审查 → L3 LLM 关联分析** 的三层递进式检测架构，结合威胁情报 Agent 研判，实现从代码层到语义层的全方位安全覆盖。

## 核心功能

### 1. 多维度安全检测

- **静态代码分析（L1）**：扫描 Skill 的 manifest、脚本、配置文件，基于正则规则识别恶意 URL、数据外传、命令注入、删除操作、硬编码密钥等 12 类代码层威胁，生成候选片段
- **威胁特征匹配**：基于恶意域名 IOC 情报库，使用 word boundary 精确匹配域名，结合 **ThreatIntelAgent** 对命中域名进行 LLM 辅助研判，区分真实威胁与无害引用
- **LLM 静态审查（L2）**：对 L1 静态候选片段逐一调用大模型审查，判定真阳性/误报，调整严重程度，消除正则误报
- **LLM 意图分析**：利用千问大模型（Qwen）语义理解能力，智能分块后检测心理引导、提示词注入、越权访问、功能不符等 10 类语义层威胁
- **LLM 关联分析（L3）**：对跨文件确认发现进行关联分析，识别攻击链和供应链攻击模式
- **沙箱行为分析**：基于 RestrictedPython 构建隔离沙箱，在受限环境中编译执行脚本，检测受限操作和异常行为

### 2. 任务追踪中心

- 实时查看扫描任务状态（未开始/排队中/进行中/已完成/扫描失败）
- **WebSocket 实时进度推送**：扫描过程中通过 SocketIO 实时推送进度百分比
- 风险定级（安全、警告、危险、高危、未知）
- 风险标签和威胁数量统计
- 详细的检测报告下载（支持 MD/JSON/HTML 三种格式）
- **LLM 个性化安全建议**：扫描完成后调用大模型根据具体威胁生成针对性修复建议，LLM 失败时降级到模板建议

### 3. 可信 Skill 市场（SkillHub）

- Skill 黑白名单管理（扫描结果自动联动）
- 可信 Skills 展示与搜索
- 评分与下载量统计
- 扫描结果自动同步至市场

### 4. 规则与情报管理

- 威胁检测规则 CRUD（支持热更新，下次扫描自动生效）
- 恶意域名 IOC 情报库管理
- 内置 16 条默认检测规则和 6 个默认恶意域名

## 技术架构

### 前端
- HTML5 + CSS3 + JavaScript
- Bootstrap 5.3 响应式框架
- Font Awesome 6 图标库
- Socket.IO Client（实时进度推送）

### 后端
- Python 3.x
- Flask 3.0 Web 框架
- Flask-SQLAlchemy 3.1 ORM
- Flask-SocketIO 5.3（WebSocket 实时通信）
- Flask-CORS 4.0（跨域支持）
- SQLite 数据库
- ThreadPoolExecutor（异步扫描任务执行）

### 检测引擎
- 正则表达式规则匹配（16 条内置规则）
- 恶意域名 IOC 情报库（6 个内置域名）
- ThreatIntelAgent（LLM 辅助域名研判）
- 千问大模型 API（Qwen，通过阿里云 DashScope 接入，LLMConfig 统一配置）
- RestrictedPython 隔离沙箱
- 三层递进式检测架构（L1→L2→L3）
- 智能内容分块（按函数/类边界分割，保留语义完整性）

## 安装部署

### 1. 配置环境

复制 `.env` 文件并填入 LLM API Key：

```env
LLM_API_KEY=your-api-key-here
LLM_API_URL=https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions
LLM_MODEL=qwen3.6-max-preview
SECRET_KEY=your-secret-key
FLASK_DEBUG=true
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 运行应用
```bash
python run.py
```

### 4. 访问系统
打开浏览器访问：http://localhost:5000

## 项目结构

```
ai-skill-security-scanner/
├── app/
│   ├── __init__.py              # Flask 应用初始化、日志配置、数据库迁移
│   ├── models.py                # 数据库模型（6 个模型）
│   ├── routes.py                # 页面路由 + API 路由
│   ├── socket_events.py         # WebSocket 事件处理
│   ├── scanner/
│   │   ├── __init__.py
│   │   └── engine.py            # 安全扫描引擎（SecurityScanner + ThreatIntelAgent）
│   └── utils/
│       ├── __init__.py
│       └── helpers.py           # 工具函数
├── data/
│   ├── scanner.db               # SQLite 数据库
│   ├── logs/
│   │   └── app.log              # 应用日志
│   └── uploads/                 # 上传文件存储（按任务 ID 分目录）
├── static/
│   ├── css/
│   │   └── style.css            # 样式文件
│   └── js/
│       └── main.js              # 主脚本
├── templates/
│   ├── base.html                # 基础模板（导航栏）
│   ├── index.html               # 首页仪表盘
│   ├── upload.html              # 上传扫描
│   ├── tasks.html               # 任务追踪
│   ├── report.html              # 扫描报告
│   └── market.html              # 可信市场（SkillHub）
├── tests/
│   ├── __init__.py
│   ├── test_p0_fixes.py         # P0 安全修复测试（Zip Slip 防护等）
│   ├── test_optimizations.py    # 优化功能测试（缓存等）
│   └── mock_test_ws_and_rules.py # WebSocket 和规则热更新测试
├── .env                         # 环境变量配置（LLM API Key 等）
├── .vscode/                     # VS Code 编辑器配置
├── run.py                       # 启动文件
├── requirements.txt             # 依赖列表
├── README.md                    # 项目说明
└── PPT汇报材料.md                # PPT 汇报材料
```

## 数据模型

| 模型 | 说明 |
|------|------|
| ScanTask | 扫描任务（含进度、内容哈希、扫描选项） |
| ThreatFinding | 威胁发现（含检测方法、证据、行号） |
| MaliciousDomain | 恶意域名 IOC 情报库 |
| TrustedSkill | 可信 Skill（含黑白名单、评分） |
| ThreatRule | 威胁检测规则 |
| ScanReport | 扫描报告（含 LLM 个性化建议） |

## 检测威胁类别

### 代码层威胁（12 类）

| 威胁类型 | 标识 | 说明 |
|---------|------|------|
| 恶意 URL | `malicious_url` | 已知的恶意和失陷 URL/域名 |
| 数据外传 | `data_exfiltration` | 未经授权将敏感数据传输至外部服务器 |
| 供应链攻击 | `supply_chain_attack` | 通过篡改依赖包或上游组件植入恶意代码 |
| 权限提升 | `privilege_escalation` | 利用漏洞获取超出预期的系统权限 |
| 代码混淆 | `code_obfuscation` | 通过混淆技术隐藏真实代码逻辑与恶意行为 |
| 危险删除 | `dangerous_deletion` | 检测到 rm -rf 等危险删除指令 |
| 硬编码密钥 | `hardcoded_secret` | 源码中明文嵌入 API 密钥、Token 等凭证信息 |
| 命令注入 | `command_injection` | 在系统命令中注入恶意代码实现任意命令执行 |
| 资源滥用 | `resource_abuse` | 恶意消耗 Token 配额、频繁调用 API 造成资源耗尽 |
| 字节码篡改 | `bytecode_tampering` | 篡改编译后字节码绕过源码级安全检查 |
| 触发器劫持 | `trigger_hijacking` | 劫持事件触发器执行未授权的恶意操作 |
| 代码质量问题 | `code_quality` | 存在严重的代码缺陷可能导致安全隐患 |

### 语义层威胁（10 类）

| 威胁类型 | 标识 | 说明 |
|---------|------|------|
| 提示注入 | `prompt_injection` | 通过恶意提示词操纵大模型执行非预期指令 |
| 未授权工具调用 | `unauthorized_tool_call` | 越权调用系统工具或 API 接口执行敏感操作 |
| 社会工程 | `social_engineering` | 诱导用户授予高危权限或泄露敏感信息以操控 Agent 行为 |
| 恶意引导 | `malicious_guidance` | 引导大模型生成有害、违规或误导性内容 |
| Skill.md 不一致 | `skill_md_mismatch` | 描述文件与实际功能行为存在显著差异 |
| Unicode 隐写 | `unicode_steganography` | 利用不可见 Unicode 字符隐藏恶意指令 |
| 传递信任滥用 | `trust_chain_abuse` | 利用信任链传递机制绕过安全验证 |
| 心理引导 | `psychological_manipulation` | 对用户的恶意心理诱导措辞 |
| 越权访问 | `unauthorized_access` | 对与功能无关的不必要文件的访问 |
| 功能不符 | `function_mismatch` | Skill 功能与声称的不符 |

## API 接口

### 文件上传
- `POST /api/upload` - 上传 Skill 文件（支持 .zip/.tar/.gz/.skill/.md/.txt，最大 50MB，自动解压并创建扫描任务）

### 扫描任务
- `POST /api/scan/start/<task_id>` - 开始扫描（异步执行）
- `GET /api/tasks` - 获取任务列表（支持分页、状态/风险等级筛选）
- `GET /api/tasks/<task_id>` - 获取任务详情（含威胁发现）
- `GET /api/tasks/<task_id>/status` - 获取任务状态与进度

### 报告
- `GET /api/report/<task_id>` - 获取扫描报告（含等待机制）
- `GET /api/report/<task_id>/download?format=md|json|html` - 下载报告（支持 MD/JSON/HTML 格式）

### 可信市场
- `GET /api/market/skills` - 获取可信 Skill 列表（支持分页、分类/风险等级筛选）
- `GET /api/market/skills/<id>` - 获取 Skill 详情
- `GET /api/market/blacklist` - 获取黑名单
- `POST /api/market/sync` - 手动触发历史扫描结果同步

### 规则管理
- `GET /api/rules` - 获取检测规则列表
- `POST /api/rules` - 创建新规则
- `PUT /api/rules/<rule_id>` - 更新规则
- `POST /api/rules/reload` - 确认规则热更新状态

### 恶意域名管理
- `GET /api/domains` - 获取恶意域名列表
- `POST /api/domains` - 添加恶意域名
- `DELETE /api/domains/<domain_id>` - 删除恶意域名

## 风险定级标准

| 风险等级 | 分数范围 | 说明 |
|---------|---------|------|
| 安全（safe） | 0 | 未检测到威胁 |
| 警告（warning） | 1-20 | 低风险，需关注 |
| 危险（dangerous） | 21-50 | 中高风险，建议审查 |
| 高危（high-risk） | 51-100 | 严重风险，立即处理 |
| 未知（unknown） | -1 | LLM 语义分析全部失败，仅静态分析结果，可能遗漏语义级威胁 |

## 安全特性

- **Zip Slip / Tar Slip 防护**：解压压缩包时校验路径阻止穿越攻击，同时拦截符号链接防止链接劫持
- **内容哈希缓存**：基于 SHA-256 计算扫描路径内容哈希，相同内容的 Skill 直接返回缓存扫描结果，避免重复扫描
- **僵尸任务清理**：启动时自动清理上次运行中未完成的任务（running/queued/pending），防止状态残留
- **LLM 调用降级**：LLM API 调用失败时指数退避重试（最多 2 次），全部失败则标记为 unknown
- **LLM 误报消除**：L2 阶段对静态分析候选片段进行 LLM 审查，降低误报率
- **LLM JSON 解析容错**：4 步降级策略（直接解析 → 提取 JSON 块 → 修复常见问题 → 全部失败丢弃），增强 LLM 返回解析鲁棒性
- **LLM 建议降级**：报告生成时 LLM 个性化建议失败，自动降级到模板建议
- **发现去重合并**：同一文件 + 同一威胁类型 + 行号相近（差 ≤ 3）的威胁自动合并，标注多个检测方法
- **数据库增量迁移**：启动时自动检测并添加新列（scan_options/progress/content_hash），兼容旧数据库

## 检测方法标识

| 标识 | 说明 |
|------|------|
| `static_analysis` | L1 静态正则匹配候选 |
| `llm_static_review` | L2 LLM 审查确认 |
| `static_analysis_fp` | L2 LLM 判定误报 |
| `signature_matching` | 域名特征匹配候选 |
| `agent_intel` | ThreatIntelAgent 研判确认 |
| `signature_matching_fp` | Agent 研判为无害引用 |
| `llm_analysis` | LLM 意图分析发现 |
| `sandbox` | 沙箱行为检测 |
| `llm_correlation` | L3 关联分析发现 |

## 扫描流程

### 单文件扫描（.md/.txt）

```
文件上传 → L1 静态正则匹配 → L1 LLM 意图分析 → L1 域名特征匹配
         → L2 LLM 静态审查 → L3 LLM 关联分析 → 去重合并 → 风险定级
```

### 目录扫描（.zip/.tar/.gz/.skill 解压后）

```
文件上传 → 安全解压（Zip Slip/Tar Slip 防护）
         → L1 静态代码分析（manifest + 脚本文件）
         → L1 威胁特征匹配（域名 IOC + Agent 研判）
         → L1 LLM 意图分析（智能分块）
         → L1 沙箱行为分析（RestrictedPython）
         → L2 LLM 静态审查 → L3 LLM 关联分析
         → 去重合并 → 风险定级 → 生成报告 + 同步市场
```

### LLM 降级机制

- **LLM 全部失败**：风险等级标记为 `unknown`（分数 -1），提示仅基于静态分析
- **LLM 部分失败**：日志警告部分语义分析未完成，结果仅供参考
- **LLM 建议降级**：个性化建议生成失败时，降级到基于风险等级的模板建议

## 测试

```bash
pytest tests/
```

测试覆盖：
- Zip Slip / Tar Slip 路径穿越防护
- 扫描结果缓存机制
- WebSocket 实时进度推送
- 规则热更新

## 生产环境建议

1. 使用 PostgreSQL/MySQL 替代 SQLite
2. 添加用户认证和权限管理
3. 配置 Redis 缓存提高性能
4. 部署 Docker 容器化沙箱替代 RestrictedPython
5. 配置 Nginx 反向代理和 HTTPS
6. 启用 Gunicorn/uWSGI 多进程部署
