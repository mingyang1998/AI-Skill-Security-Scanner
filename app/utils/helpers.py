"""
Helper utilities for the AI Skill Security Scanner
"""

import os
import re
import hashlib
from datetime import datetime

def get_file_hash(file_path, algorithm='sha256'):
    """Calculate file hash"""
    hash_obj = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal"""
    return re.sub(r'[^\w\-.]', '_', filename)

def get_file_extension(filename):
    """Get file extension"""
    return os.path.splitext(filename)[1].lower()

def is_text_file(file_path):
    """Check if file is text file"""
    text_extensions = {'.txt', '.md', '.py', '.js', '.json', '.yaml', '.yml', 
                      '.xml', '.html', '.css', '.sh', '.bat', '.ps1'}
    return get_file_extension(file_path) in text_extensions

def format_timestamp(timestamp):
    """Format timestamp to readable string"""
    if isinstance(timestamp, (int, float)):
        timestamp = datetime.fromtimestamp(timestamp)
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')

def truncate_string(text, max_length=100):
    """Truncate string with ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + '...'

def parse_risk_tags(tags_json):
    """Parse risk tags from JSON string"""
    import json
    try:
        return json.loads(tags_json) if tags_json else []
    except (json.JSONDecodeError, TypeError):
        return []

def calculate_severity_counts(findings):
    """Calculate counts by severity"""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for finding in findings:
        severity = finding.get('severity', 'low')
        counts[severity] = counts.get(severity, 0) + 1
    return counts

def get_threat_description(threat_type):
    """Get human readable threat description"""
    descriptions = {
        # === 代码层威胁 ===
        'malicious_url': '检测到已知恶意或失陷URL/域名',
        'data_exfiltration': '检测到数据外传行为',
        'supply_chain_attack': '检测到供应链攻击风险',
        'privilege_escalation': '检测到权限提升操作',
        'code_obfuscation': '检测到代码混淆行为',
        'dangerous_deletion': '检测到危险删除操作',
        'hardcoded_secret': '检测到硬编码密钥凭证',
        'command_injection': '检测到命令注入风险',
        'resource_abuse': '检测到资源滥用行为',
        'bytecode_tampering': '检测到字节码篡改风险',
        'trigger_hijacking': '检测到触发器劫持风险',
        'code_quality': '检测到代码质量问题',
        # === 语义层威胁 ===
        'prompt_injection': '检测到提示注入攻击',
        'unauthorized_tool_call': '检测到未授权工具调用',
        'social_engineering': '检测到社会工程攻击',
        'malicious_guidance': '检测到恶意引导行为',
        'skill_md_mismatch': '检测到Skill.md描述与实际功能不一致',
        'unicode_steganography': '检测到Unicode隐写术',
        'trust_chain_abuse': '检测到传递信任滥用',
        'psychological_manipulation': '检测到心理引导措辞',
        'unauthorized_access': '检测到越权访问行为',
        'function_mismatch': '检测到功能声明与实际不符',
    }
    return descriptions.get(threat_type, '未知威胁类型')
