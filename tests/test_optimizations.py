import os
import sys
import json
import hashlib
import tempfile
import shutil

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app, db
from app.models import ScanTask, ThreatFinding, ScanReport, MaliciousDomain, ThreatRule, TrustedSkill


@pytest.fixture
def app():
    os.environ['TESTING'] = '1'
    app = create_app()
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def _create_completed_task(app, task_id=None, content_hash=None, skill_name='test-skill'):
    with app.app_context():
        tid = task_id or 'task-cache-001'
        task = ScanTask(
            id=tid,
            skill_name=skill_name,
            skill_version='1.0',
            file_path='/tmp/fake',
            task_status='completed',
            risk_level='safe',
            risk_score=10,
            threat_count=0,
            content_hash=content_hash,
            progress=100
        )
        db.session.add(task)
        db.session.commit()
        return tid


class TestScanResultCache:
    """优化-11: 扫描结果缓存"""

    def test_content_hash_stored(self, app):
        with app.app_context():
            tid = _create_completed_task(app, content_hash='abc123hash')
            task = ScanTask.query.get(tid)
            assert task.content_hash == 'abc123hash'

    def test_cache_hit_returns_completed(self, app):
        with app.app_context():
            h = hashlib.sha256(b'test-content').hexdigest()
            tid = _create_completed_task(app, task_id='cached-001', content_hash=h, skill_name='cached-skill')

            finding = ThreatFinding(
                task_id=tid,
                threat_type='malicious_url',
                severity='high',
                title='test finding',
                description='desc',
                evidence='ev',
                detection_method='static_analysis'
            )
            db.session.add(finding)

            report = ScanReport(
                task_id=tid,
                report_data='{"key":"val"}',
                summary='test summary',
                recommendations='test rec'
            )
            db.session.add(report)
            db.session.commit()

            cached = ScanTask.query.filter_by(content_hash=h, task_status='completed').first()
            assert cached is not None
            assert cached.skill_name == 'cached-skill'

    def test_different_hash_no_cache(self, app):
        with app.app_context():
            _create_completed_task(app, content_hash='hash_a')
            cached = ScanTask.query.filter_by(content_hash='hash_b', task_status='completed').first()
            assert cached is None

    def test_compute_content_hash_file(self, app):
        from app.routes import _compute_content_hash
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, 'test.txt')
            with open(fpath, 'w') as f:
                f.write('hello world')
            h = _compute_content_hash(fpath)
            assert h is not None
            assert len(h) == 64
        finally:
            shutil.rmtree(tmpdir)

    def test_compute_content_hash_dir(self, app):
        from app.routes import _compute_content_hash
        tmpdir = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmpdir, 'sub'))
            with open(os.path.join(tmpdir, 'a.py'), 'w') as f:
                f.write('print(1)')
            with open(os.path.join(tmpdir, 'sub', 'b.py'), 'w') as f:
                f.write('print(2)')
            h = _compute_content_hash(tmpdir)
            assert h is not None
            assert len(h) == 64
        finally:
            shutil.rmtree(tmpdir)

    def test_compute_content_hash_nonexistent(self, app):
        from app.routes import _compute_content_hash
        h = _compute_content_hash('/nonexistent/path')
        assert h is None


class TestReportFormats:
    """优化-12: 报告格式多样化"""

    def _setup_report_data(self, app):
        with app.app_context():
            tid = 'report-fmt-001'
            task = ScanTask(
                id=tid,
                skill_name='fmt-skill',
                skill_version='2.0',
                file_path='/tmp/fake',
                task_status='completed',
                risk_level='warning',
                risk_score=40,
                threat_count=1,
                progress=100
            )
            db.session.add(task)

            finding = ThreatFinding(
                task_id=tid,
                threat_type='data_exfiltration',
                severity='high',
                title='Data leak',
                description='desc',
                evidence='requests.post',
                detection_method='static_analysis'
            )
            db.session.add(finding)

            report = ScanReport(
                task_id=tid,
                report_data='{"findings":[]}',
                summary='1 issue found',
                recommendations='Review code'
            )
            db.session.add(report)
            db.session.commit()
            return tid

    def test_download_markdown(self, app, client):
        tid = self._setup_report_data(app)
        resp = client.get(f'/api/report/{tid}/download?format=md')
        assert resp.status_code == 200
        assert resp.content_type.startswith('text/markdown')
        assert b'AI Skill' in resp.data

    def test_download_json(self, app, client):
        tid = self._setup_report_data(app)
        resp = client.get(f'/api/report/{tid}/download?format=json')
        assert resp.status_code == 200
        assert resp.content_type.startswith('application/json')
        data = json.loads(resp.data)
        assert 'task' in data
        assert 'findings' in data
        assert data['task']['skill_name'] == 'fmt-skill'

    def test_download_html(self, app, client):
        tid = self._setup_report_data(app)
        resp = client.get(f'/api/report/{tid}/download?format=html')
        assert resp.status_code == 200
        assert resp.content_type.startswith('text/html')
        assert b'fmt-skill' in resp.data
        assert b'Data leak' in resp.data

    def test_download_default_is_markdown(self, app, client):
        tid = self._setup_report_data(app)
        resp = client.get(f'/api/report/{tid}/download')
        assert resp.status_code == 200
        assert resp.content_type.startswith('text/markdown')

    def test_download_nonexistent_report(self, app, client):
        with app.app_context():
            tid = 'no-report-001'
            task = ScanTask(id=tid, skill_name='x', skill_version='1', file_path='/tmp/f', task_status='completed')
            db.session.add(task)
            db.session.commit()
        resp = client.get(f'/api/report/{tid}/download')
        assert resp.status_code == 404


class TestRuleHotReload:
    """优化-10: 规则热更新确认"""

    def test_rules_from_db(self, app):
        with app.app_context():
            rule = ThreatRule(
                rule_type='manifest',
                pattern=r'network:\s*true',
                severity='low',
                description='Test manifest rule',
                is_active=True
            )
            db.session.add(rule)
            db.session.commit()

            active = ThreatRule.query.filter_by(is_active=True, rule_type='manifest').all()
            assert len(active) >= 1
            patterns = [r.pattern for r in active]
            assert r'network:\s*true' in patterns

    def test_deactivate_rule(self, app):
        with app.app_context():
            rule = ThreatRule(
                rule_type='test_type',
                pattern='test_pattern',
                severity='medium',
                description='test',
                is_active=True
            )
            db.session.add(rule)
            db.session.commit()

            rule.is_active = False
            db.session.commit()

            active = ThreatRule.query.filter_by(rule_type='test_type', is_active=True).all()
            assert len(active) == 0

    def test_reload_endpoint(self, app, client):
        with app.app_context():
            resp = client.post('/api/rules/reload')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert 'active_rules' in data
            assert 'active_domains' in data

    def test_update_rule_endpoint(self, app, client):
        with app.app_context():
            rule = ThreatRule(
                rule_type='update_test',
                pattern='old_pattern',
                severity='low',
                description='old desc'
            )
            db.session.add(rule)
            db.session.commit()
            rule_id = rule.id

        resp = client.put(f'/api/rules/{rule_id}',
                         data=json.dumps({'severity': 'critical', 'is_active': False}),
                         content_type='application/json')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data['severity'] == 'critical'
        assert data['is_active'] is False

    def test_domains_from_db(self, app):
        with app.app_context():
            d = MaliciousDomain(domain='test-hotreload.com', severity='high', description='test')
            db.session.add(d)
            db.session.commit()

            active = MaliciousDomain.query.filter_by(is_active=True).all()
            domains = [x.domain for x in active]
            assert 'test-hotreload.com' in domains


class TestMaliciousDomainCRUD:
    """P1-6: 恶意域名 CRUD API"""

    def test_get_domains(self, app, client):
        with app.app_context():
            d = MaliciousDomain(domain='crud-test.com', severity='high')
            db.session.add(d)
            db.session.commit()
        resp = client.get('/api/domains')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        domains = [x['domain'] for x in data]
        assert 'crud-test.com' in domains

    def test_create_domain(self, app, client):
        resp = client.post('/api/domains',
                          data=json.dumps({'domain': 'new-evil.com', 'severity': 'critical'}),
                          content_type='application/json')
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert data['domain'] == 'new-evil.com'

    def test_create_duplicate_domain(self, app, client):
        with app.app_context():
            d = MaliciousDomain(domain='dup.com')
            db.session.add(d)
            db.session.commit()
        resp = client.post('/api/domains',
                          data=json.dumps({'domain': 'dup.com'}),
                          content_type='application/json')
        assert resp.status_code == 409

    def test_delete_domain(self, app, client):
        with app.app_context():
            d = MaliciousDomain(domain='del-me.com')
            db.session.add(d)
            db.session.commit()
            did = d.id
        resp = client.delete(f'/api/domains/{did}')
        assert resp.status_code == 200


class TestLazyMarketSync:
    """P2-7: _sync_historical_scans 懒加载"""

    def test_market_synced_flag(self, app):
        from app.routes import _ensure_market_synced, _market_synced
        import app.routes as routes_mod
        routes_mod._market_synced = False
        _ensure_market_synced()
        assert routes_mod._market_synced is True

    def test_market_synced_only_once(self, app):
        import app.routes as routes_mod
        routes_mod._market_synced = True
        from app.routes import _ensure_market_synced
        _ensure_market_synced()
        assert routes_mod._market_synced is True


class TestLogging:
    """P2-8: logging 日志系统"""

    def test_logger_exists(self, app):
        import logging
        logger = logging.getLogger('app.scanner.engine')
        assert logger is not None

    def test_log_file_created(self, app):
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'logs')
        assert os.path.exists(log_dir)

    def test_engine_logger_used(self, app):
        from app.scanner.engine import logger
        assert logger.name == 'app.scanner.engine'
