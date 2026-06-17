import os
import json
import uuid
import hashlib
import zipfile
import shutil
import tempfile
import tarfile
import logging
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, request, jsonify, render_template, send_file, Response
from werkzeug.utils import secure_filename
from app import db
from app import LLMConfig
from app.models import ScanTask, ThreatFinding, TrustedSkill, ThreatRule, ScanReport, MaliciousDomain
from app.scanner.engine import SecurityScanner

logger = logging.getLogger(__name__)

_scan_executor = ThreadPoolExecutor(max_workers=4)

main_bp = Blueprint('main', __name__)

# 项目根目录的绝对路径（routes.py在app/下，往上一层就是项目根）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')

ALLOWED_EXTENSIONS = {'zip', 'tar', 'gz', 'skill', 'md', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _safe_extract_zip(zip_path, extract_dir):
    """安全解压 ZIP 文件，防止 Zip Slip 路径穿越攻击"""
    abs_extract_dir = os.path.realpath(extract_dir)
    skipped = []
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            member_path = os.path.realpath(os.path.join(extract_dir, member.filename))
            if not member_path.startswith(abs_extract_dir + os.sep) and member_path != abs_extract_dir:
                logger.warning(f"Zip Slip: 跳过路径穿越成员 '{member.filename}'")
                skipped.append(member.filename)
                continue
            if member.is_dir():
                os.makedirs(member_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(member_path), exist_ok=True)
                with zip_ref.open(member) as src, open(member_path, 'wb') as dst:
                    dst.write(src.read())
    return skipped

def _safe_extract_tar(tar_path, extract_dir):
    """安全解压 TAR/TAR.GZ 文件，防止路径穿越攻击"""
    abs_extract_dir = os.path.realpath(extract_dir)
    skipped = []
    with tarfile.open(tar_path, 'r:*') as tar_ref:
        for member in tar_ref.getmembers():
            member_path = os.path.realpath(os.path.join(extract_dir, member.name))
            if not member_path.startswith(abs_extract_dir + os.sep) and member_path != abs_extract_dir:
                logger.warning(f"Tar Slip: 跳过路径穿越成员 '{member.name}'")
                skipped.append(member.name)
                continue
            if member.issym() or member.islnk():
                logger.warning(f"Tar Slip: 跳过符号链接 '{member.name}'")
                skipped.append(member.name)
                continue
            if hasattr(tarfile, 'data_filter'):
                tar_ref.extract(member, extract_dir, filter='data')
            else:
                tar_ref.extract(member, extract_dir)
    return skipped

# ==================== 页面路由 ====================

@main_bp.route('/')
def index():
    """首页仪表盘"""
    stats = {
        'total_scans': ScanTask.query.count(),
        'completed_scans': ScanTask.query.filter_by(task_status='completed').count(),
        'high_risk_count': ScanTask.query.filter(ScanTask.risk_level.in_(['high-risk', 'dangerous'])).count(),
        'trusted_skills': TrustedSkill.query.filter_by(is_blacklisted=False).count()
    }
    return render_template('index.html', stats=stats)

@main_bp.route('/upload')
def upload_page():
    """Skill上传页面"""
    return render_template('upload.html')

@main_bp.route('/tasks')
def tasks_page():
    """任务追踪页面"""
    return render_template('tasks.html')

@main_bp.route('/market')
def market_page():
    """可信Skill市场页面"""
    _ensure_market_synced()
    return render_template('market.html')

@main_bp.route('/report/<task_id>')
def report_page(task_id):
    """报告详情页面"""
    task = ScanTask.query.get_or_404(task_id)
    return render_template('report.html', task=task)

# ==================== API路由 ====================

@main_bp.route('/api/upload', methods=['POST'])
def upload_skill():
    """上传Skill文件"""
    if 'file' not in request.files:
        return jsonify({'error': '没有文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '未选择文件'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': '不支持的文件格式，仅支持.zip/.tar/.gz/.md/.txt'}), 400
    
    # 保存文件（使用绝对路径）
    task_id = str(uuid.uuid4())
    filename = secure_filename(file.filename)
    upload_dir = os.path.join(UPLOAD_DIR, task_id)
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, filename)
    file.save(file_path)
    
    # 判断文件类型，压缩包解压，普通文件直接使用
    if filename.endswith(('.zip', '.tar', '.gz', '.skill')):
        extract_dir = os.path.join(upload_dir, 'extracted')
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            if filename.endswith('.zip'):
                skipped = _safe_extract_zip(file_path, extract_dir)
            elif filename.endswith(('.tar', '.gz')):
                skipped = _safe_extract_tar(file_path, extract_dir)
            else:
                skipped = []
            if skipped:
                logger.warning(f"解压时跳过 {len(skipped)} 个路径穿越成员: {skipped[:5]}")
        except Exception as e:
            return jsonify({'error': f'解压失败: {str(e)}'}), 500
        
        scan_path = extract_dir
    else:
        # .md/.txt文件，直接扫描
        scan_path = file_path
    
    # 创建扫描任务
    skill_name = request.form.get('skill_name', filename)
    skill_version = request.form.get('skill_version', 'unknown')
    scan_options_str = request.form.get('scan_options', '{}')
    try:
        scan_options_dict = json.loads(scan_options_str)
    except (json.JSONDecodeError, TypeError):
        scan_options_dict = {}
    
    content_hash = _compute_content_hash(scan_path)
    
    cached_task = None
    if content_hash:
        cached_task = ScanTask.query.filter_by(
            content_hash=content_hash,
            task_status='completed'
        ).order_by(ScanTask.completed_at.desc()).first()
    
    if cached_task:
        task = ScanTask(
            id=task_id,
            skill_name=skill_name,
            skill_version=skill_version,
            file_path=scan_path,
            task_status='completed',
            submitted_by=request.form.get('submitter', 'anonymous'),
            scan_options=json.dumps(scan_options_dict, ensure_ascii=False),
            content_hash=content_hash,
            risk_level=cached_task.risk_level,
            risk_score=cached_task.risk_score,
            threat_count=cached_task.threat_count,
            risk_tags=cached_task.risk_tags,
            progress=100
        )
        task.completed_at = datetime.utcnow()
        db.session.add(task)
        
        cached_findings = ThreatFinding.query.filter_by(task_id=cached_task.id).all()
        for cf in cached_findings:
            new_finding = ThreatFinding(
                task_id=task_id,
                threat_type=cf.threat_type,
                severity=cf.severity,
                title=cf.title,
                description=cf.description,
                evidence=cf.evidence,
                file_location=cf.file_location,
                line_number=cf.line_number,
                detection_method=cf.detection_method
            )
            db.session.add(new_finding)
        
        cached_report = ScanReport.query.filter_by(task_id=cached_task.id).first()
        if cached_report:
            new_report = ScanReport(
                task_id=task_id,
                report_data=cached_report.report_data,
                summary=cached_report.summary,
                recommendations=cached_report.recommendations
            )
            db.session.add(new_report)
        
        db.session.commit()
        
        return jsonify({
            'message': '文件已扫描过，使用缓存结果',
            'task_id': task_id,
            'status': 'completed',
            'cached': True
        })
    
    task = ScanTask(
        id=task_id,
        skill_name=skill_name,
        skill_version=skill_version,
        file_path=scan_path,
        task_status='queued',
        submitted_by=request.form.get('submitter', 'anonymous'),
        scan_options=json.dumps(scan_options_dict, ensure_ascii=False),
        content_hash=content_hash
    )
    db.session.add(task)
    db.session.commit()
    
    return jsonify({
        'message': '文件上传成功',
        'task_id': task_id,
        'status': 'queued'
    })


@main_bp.route('/api/scan/start/<task_id>', methods=['POST'])
def start_scan(task_id):
    from flask import current_app
    task = ScanTask.query.get_or_404(task_id)
    
    if task.task_status not in ['pending', 'queued']:
        return jsonify({'error': '任务状态不允许开始扫描'}), 400
    
    task.task_status = 'running'
    task.progress = 0
    db.session.commit()
    
    app_instance = current_app._get_current_object()
    _scan_executor.submit(_run_scan, task_id, app_instance)
    
    return jsonify({
        'message': '扫描已启动',
        'task_id': task_id,
        'status': 'running'
    })


def _run_scan(task_id, app_instance):
    from app import socketio
    from app.socket_events import emit_scan_progress

    with app_instance.app_context():
        task = ScanTask.query.get(task_id)
        if not task:
            logger.error(f"扫描任务 {task_id} 不存在")
            return

        logger.info(f"[任务启动] skill={task.skill_name}, task_id={task_id}")

        rules = ThreatRule.query.filter_by(is_active=True).all()
        logger.info(f"[任务启动] 加载 {len(rules)} 条活跃检测规则")

        try:
            scan_options = json.loads(task.scan_options) if task.scan_options else None
        except (json.JSONDecodeError, TypeError):
            scan_options = None

        def update_progress(pct):
            task.progress = pct
            db.session.commit()
            emit_scan_progress(socketio, task_id, pct, 'running')
            if pct % 25 == 0 or pct == 100:
                logger.info(f"[进度更新] task_id={task_id}, progress={pct}%")

        try:
            scanner = SecurityScanner(task, rules, progress_callback=update_progress)
            result = scanner.scan_skill(task.file_path, scan_options=scan_options)

            scanner.save_findings()

            task.task_status = 'completed'
            task.risk_level = result['risk_level']
            task.risk_score = result['risk_score']
            task.threat_count = len(result['findings'])
            task.progress = 100
            task.completed_at = datetime.utcnow()

            risk_tags = list(set([f['threat_type'] for f in result['findings']]))
            task.risk_tags = json.dumps(risk_tags, ensure_ascii=False)

            db.session.commit()

            emit_scan_progress(socketio, task_id, 100, 'completed',
                             risk_level=result['risk_level'],
                             risk_score=result['risk_score'],
                             threat_count=len(result['findings']))

            logger.info(f"[任务完成] skill={task.skill_name}, risk_level={result['risk_level']}, "
                       f"risk_score={result['risk_score']}, findings={len(result['findings'])}, "
                       f"files={result['files_analyzed']}")

            _generate_report(task, result)
            _sync_skill_to_market(task, result)

        except Exception as e:
            logger.exception(f"[任务失败] task_id={task_id}, error={e}")
            task.task_status = 'failed'
            task.progress = 0
            db.session.commit()
            emit_scan_progress(socketio, task_id, 0, 'failed', error=str(e))

@main_bp.route('/api/tasks', methods=['GET'])
def get_tasks():
    """获取任务列表"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status = request.args.get('status')
    risk_level = request.args.get('risk_level')
    
    query = ScanTask.query
    
    if status:
        query = query.filter_by(task_status=status)
    if risk_level:
        query = query.filter_by(risk_level=risk_level)
    
    tasks = query.order_by(ScanTask.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'tasks': [task.to_dict() for task in tasks.items],
        'total': tasks.total,
        'pages': tasks.pages,
        'current_page': page
    })

@main_bp.route('/api/tasks/<task_id>', methods=['GET'])
def get_task(task_id):
    """获取任务详情"""
    task = ScanTask.query.get_or_404(task_id)
    findings = ThreatFinding.query.filter_by(task_id=task_id).all()
    
    return jsonify({
        'task': task.to_dict(),
        'findings': [finding.to_dict() for finding in findings]
    })

@main_bp.route('/api/tasks/<task_id>/status', methods=['GET'])
def get_task_status(task_id):
    """获取任务状态"""
    task = ScanTask.query.get_or_404(task_id)
    return jsonify({
        'task_id': task.id,
        'status': task.task_status,
        'risk_level': task.risk_level,
        'progress': _get_scan_progress(task)
    })

@main_bp.route('/api/report/<task_id>', methods=['GET'])
def get_report(task_id):
    """获取扫描报告（含等待机制，避免报告生成中的 404）"""
    task = ScanTask.query.get_or_404(task_id)

    if task.task_status == 'running':
        return jsonify({'error': '扫描进行中，报告尚未生成', 'status': 'running'}), 202

    report = ScanReport.query.filter_by(task_id=task_id).first()
    findings = ThreatFinding.query.filter_by(task_id=task_id).all()

    if not report:
        if task.task_status == 'completed':
            return jsonify({'error': '报告生成中，请稍后刷新', 'status': 'generating'}), 202
        return jsonify({'error': '报告不存在', 'status': 'not_found'}), 404

    return jsonify({
        'task': task.to_dict(),
        'report': report.to_dict(),
        'findings': [finding.to_dict() for finding in findings],
        'report_data': json.loads(report.report_data) if report.report_data else {}
    })

@main_bp.route('/api/report/<task_id>/download', methods=['GET'])
def download_report(task_id):
    """下载报告（支持 md/json/html 格式）"""
    task = ScanTask.query.get_or_404(task_id)
    report = ScanReport.query.filter_by(task_id=task_id).first()
    findings = ThreatFinding.query.filter_by(task_id=task_id).all()
    
    if not report:
        return jsonify({'error': '报告不存在'}), 404
    
    fmt = request.args.get('format', 'md').lower()
    
    skill_entry = TrustedSkill.query.filter_by(name=task.skill_name).first()
    if skill_entry:
        skill_entry.download_count = (skill_entry.download_count or 0) + 1
        db.session.commit()
    
    if fmt == 'json':
        report_json = {
            'task': task.to_dict(),
            'report': report.to_dict(),
            'findings': [f.to_dict() for f in findings],
            'report_data': json.loads(report.report_data) if report.report_data else {}
        }
        content = json.dumps(report_json, ensure_ascii=False, indent=2)
        return Response(
            content,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=scan_report_{task_id}.json'}
        )
    elif fmt == 'html':
        content = _generate_html_report(task, report, findings)
        return Response(
            content,
            mimetype='text/html',
            headers={'Content-Disposition': f'attachment; filename=scan_report_{task_id}.html'}
        )
    else:
        content = _generate_report_content(task, report)
        return Response(
            content,
            mimetype='text/markdown',
            headers={'Content-Disposition': f'attachment; filename=scan_report_{task_id}.md'}
        )

# ==================== 可信Skill市场API ====================

@main_bp.route('/api/market/skills', methods=['GET'])
def get_market_skills():
    """获取可信Skill列表"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    category = request.args.get('category')
    risk_level = request.args.get('risk_level')
    
    query = TrustedSkill.query.filter_by(is_blacklisted=False)
    
    if category:
        query = query.filter(TrustedSkill.tags.contains(category))
    if risk_level:
        query = query.filter_by(risk_level=risk_level)
    
    skills = query.order_by(TrustedSkill.download_count.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'skills': [skill.to_dict() for skill in skills.items],
        'total': skills.total,
        'pages': skills.pages,
        'current_page': page
    })

@main_bp.route('/api/market/skills/<int:skill_id>', methods=['GET'])
def get_market_skill(skill_id):
    """获取Skill详情"""
    skill = TrustedSkill.query.get_or_404(skill_id)
    return jsonify(skill.to_dict())

@main_bp.route('/api/market/blacklist', methods=['GET'])
def get_blacklist():
    """获取黑名单"""
    skills = TrustedSkill.query.filter_by(is_blacklisted=True).all()
    return jsonify([skill.to_dict() for skill in skills])

@main_bp.route('/api/market/sync', methods=['POST'])
def sync_market_data():
    """手动触发：将所有已完成的扫描任务同步到 TrustedSkill 表
    
    用于修复历史数据：确保所有已完成扫描的 Skill 结果都反映在市场页面。
    同名 Skill 去重，保留最新扫描结果。
    """
    # 获取所有已完成的扫描任务，按时间倒序（最新的优先）
    completed_tasks = ScanTask.query.filter_by(task_status='completed').order_by(ScanTask.completed_at.desc()).all()
    
    synced_count = 0
    skipped = set()
    
    for task in completed_tasks:
        # 同名 Skill 只同步最新的一次扫描
        if task.skill_name in skipped:
            continue
        skipped.add(task.skill_name)
        
        # 获取该任务的威胁发现
        findings = ThreatFinding.query.filter_by(task_id=task.id).all()
        threat_types = list(set([f.threat_type for f in findings]))
        threat_summary = '、'.join(threat_types) if threat_types else '无'
        
        # 检查是否已存在
        existing = TrustedSkill.query.filter_by(name=task.skill_name).first()
        
        if task.risk_level in ('high-risk', 'dangerous'):
            if existing:
                existing.is_blacklisted = True
                existing.risk_level = task.risk_level
                existing.blacklist_reason = f'安全扫描发现{task.threat_count}个威胁，风险评分{task.risk_score}/100。威胁类型：{threat_summary}'
                existing.updated_at = datetime.utcnow()
            else:
                blacklisted_skill = TrustedSkill(
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
                db.session.add(blacklisted_skill)
        else:
            # safe / warning
            if existing:
                existing.is_blacklisted = False
                existing.risk_level = task.risk_level
                existing.blacklist_reason = None
                existing.updated_at = datetime.utcnow()
                existing.rating = 5.0 if task.risk_level == 'safe' else 3.0
            else:
                trusted_skill = TrustedSkill(
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
                db.session.add(trusted_skill)
        
        synced_count += 1
    
    db.session.commit()
    
    return jsonify({
        'message': f'同步完成，共处理{synced_count}个扫描任务',
        'synced_count': synced_count
    })

# ==================== 规则管理API ====================

@main_bp.route('/api/rules', methods=['GET'])
def get_rules():
    """获取检测规则列表"""
    rules = ThreatRule.query.all()
    return jsonify([rule.to_dict() for rule in rules])

@main_bp.route('/api/rules', methods=['POST'])
def create_rule():
    """创建新规则"""
    data = request.get_json()
    
    rule = ThreatRule(
        rule_type=data.get('rule_type'),
        pattern=data.get('pattern'),
        severity=data.get('severity', 'medium'),
        description=data.get('description'),
        is_active=data.get('is_active', True)
    )
    db.session.add(rule)
    db.session.commit()
    
    return jsonify(rule.to_dict()), 201

@main_bp.route('/api/rules/<int:rule_id>', methods=['PUT'])
def update_rule(rule_id):
    """更新规则"""
    rule = ThreatRule.query.get_or_404(rule_id)
    data = request.get_json()
    
    if 'pattern' in data:
        rule.pattern = data['pattern']
    if 'severity' in data:
        rule.severity = data['severity']
    if 'description' in data:
        rule.description = data['description']
    if 'is_active' in data:
        rule.is_active = data['is_active']
    if 'rule_type' in data:
        rule.rule_type = data['rule_type']
    
    db.session.commit()
    return jsonify(rule.to_dict())

@main_bp.route('/api/rules/reload', methods=['POST'])
def reload_rules():
    """确认规则热更新状态"""
    active_rules = ThreatRule.query.filter_by(is_active=True).count()
    active_domains = MaliciousDomain.query.filter_by(is_active=True).count()
    return jsonify({
        'message': '规则已就绪，下次扫描自动生效',
        'active_rules': active_rules,
        'active_domains': active_domains
    })

# ==================== 恶意域名管理API ====================

@main_bp.route('/api/domains', methods=['GET'])
def get_domains():
    """获取恶意域名列表"""
    domains = MaliciousDomain.query.all()
    return jsonify([d.to_dict() for d in domains])

@main_bp.route('/api/domains', methods=['POST'])
def create_domain():
    """添加恶意域名"""
    data = request.get_json()
    existing = MaliciousDomain.query.filter_by(domain=data.get('domain')).first()
    if existing:
        return jsonify({'error': '域名已存在'}), 409
    domain = MaliciousDomain(
        domain=data.get('domain'),
        source=data.get('source', 'manual'),
        severity=data.get('severity', 'high'),
        description=data.get('description'),
        is_active=data.get('is_active', True)
    )
    db.session.add(domain)
    db.session.commit()
    return jsonify(domain.to_dict()), 201

@main_bp.route('/api/domains/<int:domain_id>', methods=['DELETE'])
def delete_domain(domain_id):
    """删除恶意域名"""
    domain = MaliciousDomain.query.get_or_404(domain_id)
    db.session.delete(domain)
    db.session.commit()
    return jsonify({'message': '删除成功'})

# ==================== 辅助函数 ====================

def _compute_content_hash(scan_path):
    """计算扫描路径下所有文件的 SHA-256 哈希"""
    try:
        h = hashlib.sha256()
        if os.path.isfile(scan_path):
            with open(scan_path, 'rb') as f:
                h.update(f.read())
        elif os.path.isdir(scan_path):
            for root, dirs, files in os.walk(scan_path):
                dirs.sort()
                for fname in sorted(files):
                    fpath = os.path.join(root, fname)
                    h.update(fname.encode('utf-8'))
                    with open(fpath, 'rb') as f:
                        for chunk in iter(lambda: f.read(8192), b''):
                            h.update(chunk)
        else:
            return None
        return h.hexdigest()
    except Exception:
        return None

_market_synced = False

def _ensure_market_synced():
    """懒加载：首次访问市场页时同步历史扫描数据"""
    global _market_synced
    if _market_synced:
        return
    _market_synced = True
    from app import _sync_historical_scans
    _sync_historical_scans()

def _get_scan_progress(task):
    """获取扫描进度"""
    if task.task_status == 'completed':
        return 100
    elif task.task_status == 'failed':
        return -1
    elif task.task_status == 'running':
        return task.progress or 0
    else:
        return 0

def _generate_report(task, result):
    """生成扫描报告（含 LLM 个性化建议）"""
    report_data = {
        'scan_summary': result['scan_summary'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'files_analyzed': result['files_analyzed'],
        'findings': result['findings']
    }

    recommendations = _generate_llm_recommendations(task, result)

    report = ScanReport(
        task_id=task.id,
        report_data=json.dumps(report_data, ensure_ascii=False),
        summary=f'扫描发现{len(result["findings"])}个问题，风险等级: {result["risk_level"]}',
        recommendations=recommendations
    )
    db.session.add(report)
    db.session.commit()


def _generate_llm_recommendations(task, result):
    """使用 LLM 生成个性化安全建议，降级到模板建议"""
    findings_summary = []
    for f in result.get('findings', [])[:15]:
        findings_summary.append(
            f"- [{f.get('severity', '?').upper()}] {f.get('threat_type', '?')}: {f.get('description', '?')[:100]}"
        )
    if len(result.get('findings', [])) > 15:
        findings_summary.append(f"- ... 共 {len(result['findings'])} 个发现")

    findings_text = '\n'.join(findings_summary) if findings_summary else '未发现威胁'

    prompt = f"""你是AI安全专家。请根据以下安全扫描结果，为 Skill 开发者/使用者提供针对性的安全建议。

Skill名称：{task.skill_name}
风险等级：{result['risk_level']}
风险评分：{result['risk_score']}/100

威胁发现：
{findings_text}

请给出3-5条具体、可操作的安全建议，每条建议应包含：
1. 问题描述
2. 修复/缓解方案
3. 优先级

以纯文本输出，每条建议用数字编号，不要输出 JSON 或代码块。"""

    if LLMConfig.API_KEY:
        try:
            headers = {
                "Authorization": f"Bearer {LLMConfig.API_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": LLMConfig.MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 1000
            }
            response = requests.post(LLMConfig.API_URL, headers=headers, json=payload, timeout=LLMConfig.TIMEOUT)
            response.raise_for_status()
            resp_json = response.json()
            usage = resp_json.get("usage", {})
            if usage:
                logger.info(f"[报告建议] token用量: prompt={usage.get('prompt_tokens', '?')}, "
                           f"completion={usage.get('completion_tokens', '?')}, "
                           f"total={usage.get('total_tokens', '?')}")
            llm_result = resp_json["choices"][0]["message"]["content"]
            if llm_result and len(llm_result.strip()) > 20:
                logger.info(f"[报告建议] LLM 生成个性化建议成功，长度={len(llm_result)}")
                return llm_result.strip()
        except Exception as e:
            logger.warning(f"[报告建议] LLM 生成建议失败，降级到模板: {e}")

    recommendations = []
    if result['risk_level'] == 'high-risk':
        recommendations.append('1. 该Skill存在高危风险，建议立即停止使用并进行深度审查')
    elif result['risk_level'] == 'dangerous':
        recommendations.append('1. 该Skill存在危险行为，建议在受控环境中使用')
    elif result['risk_level'] == 'warning':
        recommendations.append('1. 该Skill存在潜在风险，建议审查相关代码')
    elif result['risk_level'] == 'unknown':
        recommendations.append('1. LLM语义分析未完成，当前结果仅基于静态规则，可能遗漏语义级威胁，建议重新扫描')
    else:
        recommendations.append('1. 该Skill通过基础安全检测，但仍建议定期审查')

    if result['scan_summary']['by_severity'].get('critical', 0) > 0:
        recommendations.append(f'2. 发现{result["scan_summary"]["by_severity"]["critical"]}个严重级别威胁，需优先处理')

    return '\n'.join(recommendations)

def _generate_report_content(task, report):
    """生成报告文本内容"""
    findings = ThreatFinding.query.filter_by(task_id=task.id).all()
    
    content = f"""# AI Skill安全扫描报告

## 基本信息

- **扫描任务ID**: {task.id}
- **Skill名称**: {task.skill_name}
- **Skill版本**: {task.skill_version}
- **扫描状态**: {task.task_status}
- **风险等级**: {task.risk_level}
- **风险评分**: {task.risk_score}/100
- **提交时间**: {task.created_at}
- **完成时间**: {task.completed_at or '未完成'}

## 扫描摘要

{report.summary}

## 检测发现

| 序号 | 威胁类型 | 严重程度 | 检测方法 | 文件位置 | 行号 |
|------|----------|----------|----------|----------|------|
"""
    
    for i, finding in enumerate(findings, 1):
        content += f"| {i} | {finding.threat_type} | {finding.severity} | {finding.detection_method} | {finding.file_location} | {finding.line_number} |\n"
    
    content += f"""
## 详细发现

"""
    
    for finding in findings:
        content += f"""### {finding.title}

- **威胁类型**: {finding.threat_type}
- **严重程度**: {finding.severity}
- **检测方法**: {finding.detection_method}
- **文件位置**: {finding.file_location}
- **行号**: {finding.line_number}
- **描述**: {finding.description}
- **证据**: `{finding.evidence}`

---

"""
    
    content += f"""
## 安全建议

{report.recommendations}

---

*报告生成时间: {datetime.utcnow()}*
*AI Skill Security Scanner v1.0*
"""
    
    return content

def _generate_html_report(task, report, findings):
    """生成 HTML 格式报告"""
    severity_colors = {
        'critical': '#dc3545',
        'high': '#e67e22',
        'medium': '#f39c12',
        'low': '#28a745'
    }
    
    findings_rows = ''
    for i, f in enumerate(findings, 1):
        color = severity_colors.get(f.severity, '#6c757d')
        findings_rows += f'''
        <tr>
            <td>{i}</td>
            <td>{f.threat_type}</td>
            <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px">{f.severity}</span></td>
            <td>{f.detection_method}</td>
            <td title="{f.file_location}">{f.file_location.split(os.sep)[-1] if f.file_location else '-'}</td>
            <td>{f.line_number or '-'}</td>
            <td>{f.title}</td>
        </tr>'''
    
    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>AI Skill安全扫描报告 - {task.skill_name}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; color: #333; }}
h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
h2 {{ color: #2c3e50; margin-top: 30px; }}
.info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 15px 0; }}
.info-item {{ background: #f8f9fa; padding: 10px 15px; border-radius: 6px; }}
.info-label {{ font-weight: bold; color: #6c757d; font-size: 0.85em; }}
.info-value {{ font-size: 1.1em; margin-top: 2px; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
th {{ background: #2c3e50; color: #fff; }}
tr:hover {{ background: #f1f3f5; }}
.risk-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; color: #fff; font-weight: bold; }}
.risk-safe {{ background: #28a745; }}
.risk-warning {{ background: #f39c12; }}
.risk-dangerous {{ background: #e67e22; }}
.risk-high-risk {{ background: #dc3545; }}
.risk-unknown {{ background: #6c757d; }}
.recommendations {{ background: #e8f4fd; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 0 6px 6px 0; }}
footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>AI Skill安全扫描报告</h1>

<h2>基本信息</h2>
<div class="info-grid">
    <div class="info-item"><div class="info-label">Skill名称</div><div class="info-value">{task.skill_name}</div></div>
    <div class="info-item"><div class="info-label">Skill版本</div><div class="info-value">{task.skill_version}</div></div>
    <div class="info-item"><div class="info-label">风险等级</div><div class="info-value"><span class="risk-badge risk-{task.risk_level}">{task.risk_level}</span></div></div>
    <div class="info-item"><div class="info-label">风险评分</div><div class="info-value">{task.risk_score}/100</div></div>
    <div class="info-item"><div class="info-label">提交时间</div><div class="info-value">{task.created_at}</div></div>
    <div class="info-item"><div class="info-label">完成时间</div><div class="info-value">{task.completed_at or '未完成'}</div></div>
</div>

<h2>扫描摘要</h2>
<p>{report.summary}</p>

<h2>检测发现（共 {len(findings)} 项）</h2>
<table>
<thead><tr><th>#</th><th>威胁类型</th><th>严重程度</th><th>检测方法</th><th>文件</th><th>行号</th><th>标题</th></tr></thead>
<tbody>{findings_rows}</tbody>
</table>

<h2>安全建议</h2>
<div class="recommendations">{report.recommendations}</div>

<footer>报告生成时间: {datetime.utcnow()} | AI Skill Security Scanner v1.0</footer>
</body>
</html>'''

def _sync_skill_to_market(task, result):
    """扫描完成后，将结果同步到 TrustedSkill 表（白名单/黑名单联动）
    
    逻辑：
    - safe → 加入白名单（is_blacklisted=False）
    - warning → 加入白名单但标记为警告级别
    - high-risk / dangerous → 加入黑名单（is_blacklisted=True）
    - 同名 Skill 去重：保留最新扫描结果，更新风险等级
    """
    risk_level = result['risk_level']
    skill_name = task.skill_name
    
    # 查找是否已存在同名 Skill
    existing = TrustedSkill.query.filter_by(name=skill_name).first()
    
    # 构建威胁摘要作为黑名单原因
    threat_types = list(set([f['threat_type'] for f in result['findings']]))
    threat_summary = '、'.join(threat_types) if threat_types else '无'
    
    if risk_level in ('high-risk', 'dangerous'):
        # 加入黑名单
        if existing:
            # 更新为黑名单
            existing.is_blacklisted = True
            existing.risk_level = risk_level
            existing.blacklist_reason = f'安全扫描发现{len(result["findings"])}个威胁，风险评分{result["risk_score"]}/100。威胁类型：{threat_summary}'
            existing.updated_at = datetime.utcnow()
        else:
            blacklisted_skill = TrustedSkill(
                name=skill_name,
                version=task.skill_version,
                source='scanned',
                risk_level=risk_level,
                description=f'经安全扫描判定为{risk_level}风险，包含{len(result["findings"])}个安全威胁',
                author=task.submitted_by or 'Unknown',
                is_blacklisted=True,
                blacklist_reason=f'安全扫描发现{len(result["findings"])}个威胁，风险评分{result["risk_score"]}/100。威胁类型：{threat_summary}',
                download_count=0,
                rating=0.0
            )
            db.session.add(blacklisted_skill)
    else:
        # safe / warning / unknown → 加入白名单
        if existing:
            existing.is_blacklisted = False
            existing.risk_level = risk_level
            existing.blacklist_reason = None
            existing.updated_at = datetime.utcnow()
            if risk_level == 'safe':
                existing.rating = 5.0
                existing.description = f'经安全扫描验证，未发现安全威胁（风险评分{result["risk_score"]}/100）'
            elif risk_level == 'unknown':
                existing.rating = 2.0
                existing.description = f'LLM语义分析未完成，结果仅基于静态规则，建议重新扫描'
            else:
                existing.rating = 3.0
                existing.description = f'经安全扫描发现低风险问题，风险评分{result["risk_score"]}/100'
        else:
            if risk_level == 'unknown':
                desc = 'LLM语义分析未完成，结果仅基于静态规则，建议重新扫描'
                rating = 2.0
            elif risk_level == 'safe':
                desc = f'经安全扫描验证，风险评分{result["risk_score"]}/100'
                rating = 5.0
            else:
                desc = f'经安全扫描发现低风险问题，风险评分{result["risk_score"]}/100'
                rating = 3.0
            trusted_skill = TrustedSkill(
                name=skill_name,
                version=task.skill_version,
                source='scanned',
                risk_level=risk_level,
                description=desc,
                author=task.submitted_by or 'Unknown',
                is_blacklisted=False,
                download_count=0,
                rating=rating
            )
            db.session.add(trusted_skill)
    
    db.session.commit()
