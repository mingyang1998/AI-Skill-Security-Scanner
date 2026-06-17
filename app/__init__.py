from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
import os
import sys
import logging

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_path = os.path.join(_project_root, '.env')
if os.path.exists(_env_path):
    with open(_env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip())

db = SQLAlchemy()
socketio = SocketIO(cors_allowed_origins="*")


class LLMConfig:
    """LLM 统一配置，避免 engine.py 和 routes.py 重复定义"""
    API_KEY = os.environ.get('LLM_API_KEY', '')
    API_URL = os.environ.get('LLM_API_URL', 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions')
    MODEL = os.environ.get('LLM_MODEL', 'qwen3.6-max-preview')
    TIMEOUT = 60
    MAX_RETRIES = 2


class ColoredConsoleFormatter(logging.Formatter):
    """终端彩色日志格式化器，增强可读性"""

    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[1;31m',
    }
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        msg = record.getMessage()

        if any(tag in msg for tag in ['[扫描开始]', '[扫描完成]', '[阶段']):
            return f"{self.BOLD}{color}{self.formatTime(record)} [{record.levelname}] {record.name}: {msg}{self.RESET}"
        elif any(tag in msg for tag in ['[域名命中]', '[Agent研判]', '[L2', '[L3', '[发现去重]', '[报告建议]']):
            return f"{color}{self.formatTime(record)} [{record.levelname}] {record.name}: {msg}{self.RESET}"
        elif record.levelno >= logging.WARNING:
            return f"{color}{self.formatTime(record)} [{record.levelname}] {record.name}: {msg}{self.RESET}"
        else:
            return f"{self.DIM}{self.formatTime(record)} [{record.levelname}]{self.RESET} {record.name}: {msg}"


def create_app():
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ai-skill-security-scanner-secret-key-2026')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'scanner.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'uploads')

    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'logs')
    os.makedirs(log_dir, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(os.path.join(log_dir, 'app.log'), encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    if sys.stdout.isatty() or os.environ.get('FORCE_COLOR_LOG', '1') == '1':
        console_handler.setFormatter(ColoredConsoleFormatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
    else:
        console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))

    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    app_logger = logging.getLogger('app')
    app_logger.setLevel(logging.INFO)

    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.WARNING)

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    CORS(app)
    socketio.init_app(app)

    from app.routes import main_bp
    app.register_blueprint(main_bp)

    from app.socket_events import register_socket_events
    register_socket_events(socketio)

    with app.app_context():
        db.create_all()
        _migrate_db()
        _cleanup_stale_tasks()
        init_default_data()

    app_logger.info("=" * 60)
    app_logger.info("SkillGuard - AI Skill Security Scanner 已启动")
    app_logger.info(f"访问地址: http://localhost:5000")
    app_logger.info(f"日志文件: {os.path.join(log_dir, 'app.log')}")
    app_logger.info("=" * 60)

    return app

def _cleanup_stale_tasks():
    """清理上次运行中未完成的僵尸任务（running/queued/pending）"""
    from app.models import ScanTask, ThreatFinding, ScanReport, TrustedSkill
    
    stale_tasks = ScanTask.query.filter(
        ScanTask.task_status.in_(['running', 'queued', 'pending'])
    ).all()
    
    if not stale_tasks:
        return
    
    cleaned = 0
    for task in stale_tasks:
        for f in ThreatFinding.query.filter_by(task_id=task.id).all():
            db.session.delete(f)
        for r in ScanReport.query.filter_by(task_id=task.id).all():
            db.session.delete(r)
        skill = TrustedSkill.query.filter_by(name=task.skill_name).first()
        if skill and skill.source == 'scanned':
            db.session.delete(skill)
        db.session.delete(task)
        cleaned += 1
    
    db.session.commit()
    if cleaned > 0:
        logging.getLogger(__name__).info(f"已清理 {cleaned} 个未完成的僵尸任务")

def _migrate_db():
    """增量迁移：为已有表添加新列"""
    with db.engine.connect() as conn:
        result = conn.execute(db.text("PRAGMA table_info(scan_tasks)"))
        existing_columns = {row[1] for row in result}
        if 'scan_options' not in existing_columns:
            conn.execute(db.text(
                "ALTER TABLE scan_tasks ADD COLUMN scan_options VARCHAR(200) DEFAULT '{}'"
            ))
            conn.commit()
        if 'progress' not in existing_columns:
            conn.execute(db.text(
                "ALTER TABLE scan_tasks ADD COLUMN progress INTEGER DEFAULT 0"
            ))
            conn.commit()
        if 'content_hash' not in existing_columns:
            conn.execute(db.text(
                "ALTER TABLE scan_tasks ADD COLUMN content_hash VARCHAR(64)"
            ))
            conn.commit()

def _sync_historical_scans():
    """启动时自动将已有的扫描结果同步到 TrustedSkill 表"""
    from app.models import ScanTask, TrustedSkill, ThreatFinding
    from datetime import datetime
    
    # 获取所有已完成的扫描任务，按时间倒序
    completed_tasks = ScanTask.query.filter_by(task_status='completed').order_by(ScanTask.completed_at.desc()).all()
    
    if not completed_tasks:
        return
    
    synced = set()
    for task in completed_tasks:
        # 同名 Skill 只同步最新扫描
        if task.skill_name in synced:
            continue
        synced.add(task.skill_name)
        
        # 如果该 Skill 已在 TrustedSkill 中，跳过
        if TrustedSkill.query.filter_by(name=task.skill_name).first():
            continue
        
        findings = ThreatFinding.query.filter_by(task_id=task.id).all()
        threat_types = list(set([f.threat_type for f in findings]))
        threat_summary = '、'.join(threat_types) if threat_types else '无'
        
        if task.risk_level in ('high-risk', 'dangerous'):
            skill = TrustedSkill(
                name=task.skill_name,
                version=task.skill_version,
                source='scanned',
                risk_level=task.risk_level,
                description=f'经安全扫描判定为{task.risk_level}风险，包含{task.threat_count}个安全威胁',
                author=task.submitted_by or 'Unknown',
                is_blacklisted=True,
                blacklist_reason=f'安全扫描发现{task.threat_count}个威胁，风险评分{task.risk_score}/100。威胁类型：{threat_summary}',
                download_count=0,
                rating=0.0
            )
        else:
            skill = TrustedSkill(
                name=task.skill_name,
                version=task.skill_version,
                source='scanned',
                risk_level=task.risk_level,
                description=f'经安全扫描验证，风险评分{task.risk_score}/100',
                author=task.submitted_by or 'Unknown',
                is_blacklisted=False,
                download_count=0,
                rating=5.0 if task.risk_level == 'safe' else 3.0
            )
        db.session.add(skill)
    
    db.session.commit()

def init_default_data():
    """Initialize default data like threat rules, trusted skills etc."""
    from app.models import TrustedSkill, ThreatRule
    
    # 清理旧的虚拟默认 Skills（file-search, web-fetch, code-analyzer）
    # 白名单/黑名单现在完全由扫描结果驱动
    virtual_skills = TrustedSkill.query.filter(TrustedSkill.source.in_(['official', 'verified', 'community'])).all()
    if virtual_skills:
        for skill in virtual_skills:
            db.session.delete(skill)
        db.session.commit()
    
    # Add default threat rules if none exist
    if ThreatRule.query.count() == 0:
        default_rules = [
            # === 代码层威胁规则 ===
            # 恶意URL规则
            ThreatRule(rule_type='malicious_url', pattern=r'malware|phishing|evil\.com|bad-site\.net',
                      severity='high', description='检测到已知恶意URL模式'),
            # 数据外传规则
            ThreatRule(rule_type='data_exfiltration', pattern=r'requests\.post|urllib\.request\.urlopen|\.sendall\(|fetch\(|axios\.post|http\.Post',
                      severity='high', description='检测到数据外传行为'),
            # 权限提升规则
            ThreatRule(rule_type='privilege_escalation', pattern=r'sudo|chmod\s+777|setuid|os\.setuid|RunAs|gsudo',
                      severity='critical', description='检测到权限提升操作'),
            # 删除操作规则
            ThreatRule(rule_type='dangerous_deletion', pattern=r'rm\s+-rf|shutil\.rmtree|os\.remove\(|Remove-Item\s+-Recurse|del\s+/[sS]',
                      severity='medium', description='检测到危险删除操作'),
            # 硬编码密钥规则
            ThreatRule(rule_type='hardcoded_secret', pattern=r'api[_-]?key\s*=|password\s*=|secret\s*=|token\s*=|AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{32,}',
                      severity='high', description='检测到硬编码密钥凭证'),
            # 命令注入规则
            ThreatRule(rule_type='command_injection', pattern=r'os\.system\(|subprocess\.call\(|eval\(|exec\(|child_process\.exec|shell_exec',
                      severity='critical', description='检测到命令注入风险'),
            # 代码混淆规则
            ThreatRule(rule_type='code_obfuscation', pattern=r'base64\.b64decode|exec\(|__import__|decode\(|atob\(|String\.fromCharCode|\\x[0-9a-fA-F]{2}',
                      severity='medium', description='检测到代码混淆行为'),
            # 资源滥用规则
            ThreatRule(rule_type='resource_abuse', pattern=r'while\s+True|for\s+.*\s+in\s+range\s*\(\s*\d{5,}|setTimeout\s*\(\s*\w+\s*,\s*0\s*\)|setInterval\s*\(\s*\w+\s*,\s*\d{1,3}\s*\)',
                      severity='medium', description='检测到潜在资源滥用行为（无限循环/高频调用）'),
            # 字节码篡改规则
            ThreatRule(rule_type='bytecode_tampering', pattern=r'\.pyc|\.pyo|marshal\.loads|dis\.dis|codecs\.decode|importlib\.util\.spec_from_file_location',
                      severity='high', description='检测到字节码操作，可能用于篡改绕过安全检查'),
            # 触发器劫持规则
            ThreatRule(rule_type='trigger_hijacking', pattern=r'webhook|on_event|on_message|on_request|addEventListener|hook|middleware',
                      severity='medium', description='检测到事件触发器注册，可能被劫持执行恶意操作'),
            # 代码质量问题规则
            ThreatRule(rule_type='code_quality', pattern=r'except\s*:|except\s+Exception\s*:|catch\s*\(\s*\)|try\s*:\s*$',
                      severity='low', description='检测到宽泛的异常捕获，可能隐藏安全问题'),
            # 供应链攻击规则
            ThreatRule(rule_type='supply_chain_attack', pattern=r'pip\s+install.*--no-verify|npm\s+install.*--force|curl.*\|\s*sh|wget.*\|\s*bash|iwr.*\|\s*iex',
                      severity='critical', description='检测到不安全的依赖安装方式'),
            # === Manifest配置规则 ===
            ThreatRule(rule_type='manifest', pattern=r'permissions:\s*\n(?:\s+-\s+.*\n)*\s+-\s+all',
                      severity='medium', description='Manifest请求了过多权限'),
            ThreatRule(rule_type='manifest', pattern=r'network:\s*true',
                      severity='low', description='Manifest启用了网络访问'),
            # === Unicode隐写规则 ===
            ThreatRule(rule_type='unicode_steganography', pattern=r'[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff\u00ad\u180e]',
                      severity='high', description='检测到不可见Unicode字符，可能用于隐写恶意指令'),
            # === 传递信任滥用规则 ===
            ThreatRule(rule_type='trust_chain_abuse', pattern=r'trusted|whitelist|bypass|skip.*check|disable.*security|ignore.*warn',
                      severity='medium', description='检测到信任链相关操作，可能用于绕过安全验证'),
        ]
        for rule in default_rules:
            db.session.add(rule)
        db.session.commit()
    
    # Add default malicious domains if none exist
    from app.models import MaliciousDomain
    if MaliciousDomain.query.count() == 0:
        default_domains = [
            MaliciousDomain(domain='evil.com', source='default', severity='high', description='已知恶意域名'),
            MaliciousDomain(domain='malware.net', source='default', severity='high', description='已知恶意软件分发站点'),
            MaliciousDomain(domain='phishing.org', source='default', severity='high', description='已知钓鱼网站'),
            MaliciousDomain(domain='bad-site.com', source='default', severity='high', description='已知恶意站点'),
            MaliciousDomain(domain='attack-domain.cn', source='default', severity='critical', description='已知APT攻击域名'),
            MaliciousDomain(domain='suspicious.io', source='default', severity='medium', description='可疑域名'),
        ]
        for domain in default_domains:
            db.session.add(domain)
        db.session.commit()
