import sys
import time
import json

sys.path.insert(0, '.')

from app import create_app, db, socketio
from app.models import ScanTask, ThreatFinding, ScanReport, ThreatRule, MaliciousDomain
from app.socket_events import emit_scan_progress

app = create_app()
app.config['TESTING'] = True

MOCK_TASK_IDS = []


def cleanup_mock_tasks():
    for tid in MOCK_TASK_IDS:
        task = ScanTask.query.get(tid)
        if task:
            for f in ThreatFinding.query.filter_by(task_id=tid).all():
                db.session.delete(f)
            for r in ScanReport.query.filter_by(task_id=tid).all():
                db.session.delete(r)
            db.session.delete(task)
    if MOCK_TASK_IDS:
        db.session.commit()
        print(f"\n[清理] 已删除 {len(MOCK_TASK_IDS)} 个 mock 测试任务")


print("=" * 60)
print("WebSocket 实时进度 + 规则热更新 Mock 测试")
print("=" * 60)

with app.app_context():
    db.create_all()

    try:
        # ===== 测试 1: SocketIO test_client 验证进度推送 =====
        print("\n--- 测试 1: SocketIO 进度推送（test_client） ---")

        task_id = 'ws-mock-001'
        MOCK_TASK_IDS.append(task_id)
        existing = ScanTask.query.get(task_id)
        if existing:
            db.session.delete(existing)
            db.session.commit()

        task = ScanTask(
            id=task_id,
            skill_name='ws-mock-skill',
            skill_version='1.0',
            file_path='/tmp/fake',
            task_status='running',
            progress=0
        )
        db.session.add(task)
        db.session.commit()

        client = socketio.test_client(app)
        assert client.is_connected(), "SocketIO 客户端连接失败"
        print("  [✅] SocketIO test_client 已连接")

        client.emit('join_task', {'task_id': task_id})
        time.sleep(0.2)

        received = []

        stages = [
            (10, 'running'),
            (25, 'running'),
            (50, 'running'),
            (75, 'running'),
            (100, 'completed'),
        ]

        for pct, status in stages:
            task.progress = pct
            if status == 'completed':
                task.task_status = 'completed'
                task.risk_level = 'safe'
                task.risk_score = 10
            db.session.commit()

            emit_scan_progress(socketio, task_id, pct, status)

            time.sleep(0.1)

            events = client.get_received()
            for ev in events:
                if ev.get('name') == 'scan_progress':
                    data = ev.get('args', [{}])[0]
                    received.append(data)
                    print(f"  [收到] progress={data.get('progress')}%, status={data.get('status')}")

        client.disconnect()

        print(f"\n  共收到 {len(received)} 个事件")
        if len(received) >= 4:
            print("  [✅ 通过] WebSocket 实时进度推送正常")
        else:
            print("  [❌ 失败] 事件数不足")

        # ===== 测试 2: 规则热更新 =====
        print("\n--- 测试 2: 规则热更新 ---")

        initial_count = ThreatRule.query.filter_by(is_active=True).count()
        print(f"  初始活跃规则数: {initial_count}")

        new_rule = ThreatRule(
            rule_type='hot_reload_test',
            pattern=r'hot_reload_pattern_\d+',
            severity='high',
            description='热更新测试规则',
            is_active=True
        )
        db.session.add(new_rule)
        db.session.commit()
        after_add = ThreatRule.query.filter_by(is_active=True).count()
        print(f"  新增后活跃规则数: {after_add} (期望 {initial_count + 1})")
        assert after_add == initial_count + 1, "新增规则未生效"
        print("  [✅] 新增规则即时生效")

        new_rule.is_active = False
        db.session.commit()
        after_disable = ThreatRule.query.filter_by(is_active=True).count()
        print(f"  禁用后活跃规则数: {after_disable} (期望 {initial_count})")
        assert after_disable == initial_count, "禁用规则未生效"
        print("  [✅] 禁用规则即时生效")

        new_rule.severity = 'critical'
        new_rule.pattern = r'updated_hot_reload_v2'
        new_rule.is_active = True
        db.session.commit()
        updated = db.session.get(ThreatRule, new_rule.id)
        assert updated.severity == 'critical' and updated.pattern == r'updated_hot_reload_v2'
        print("  [✅] 修改规则即时生效")

        db.session.delete(new_rule)
        db.session.commit()

        # ===== 测试 3: 恶意域名热更新 =====
        print("\n--- 测试 3: 恶意域名热更新 ---")

        initial_domains = MaliciousDomain.query.filter_by(is_active=True).count()
        print(f"  初始活跃域名数: {initial_domains}")

        new_domain = MaliciousDomain(
            domain='hot-reload-test.evil',
            severity='critical',
            description='热更新测试域名'
        )
        db.session.add(new_domain)
        db.session.commit()
        after_add = MaliciousDomain.query.filter_by(is_active=True).count()
        assert after_add == initial_domains + 1
        print("  [✅] 新增域名即时生效")

        new_domain.is_active = False
        db.session.commit()
        after_disable = MaliciousDomain.query.filter_by(is_active=True).count()
        assert after_disable == initial_domains
        print("  [✅] 禁用域名即时生效")

        db.session.delete(new_domain)
        db.session.commit()

        # ===== 测试 4: 规则 API 端点 =====
        print("\n--- 测试 4: 规则管理 API 端点 ---")

        flask_client = app.test_client()

        resp = flask_client.get('/api/rules')
        rules = json.loads(resp.data)
        print(f"  GET /api/rules -> {len(rules)} 条规则")

        resp = flask_client.post('/api/rules',
                                 data=json.dumps({
                                     'rule_type': 'api_test',
                                     'pattern': r'api_test_\w+',
                                     'severity': 'low',
                                     'description': 'API测试规则'
                                 }),
                                 content_type='application/json')
        assert resp.status_code == 201
        new_rule_data = json.loads(resp.data)
        rule_id = new_rule_data['id']
        print(f"  POST /api/rules -> 创建 ID={rule_id}")

        resp = flask_client.put(f'/api/rules/{rule_id}',
                                data=json.dumps({'severity': 'critical', 'is_active': False}),
                                content_type='application/json')
        assert resp.status_code == 200
        updated_data = json.loads(resp.data)
        assert updated_data['severity'] == 'critical' and updated_data['is_active'] is False
        print(f"  PUT /api/rules/{rule_id} -> severity=critical, is_active=False")

        resp = flask_client.post('/api/rules/reload')
        assert resp.status_code == 200
        reload_data = json.loads(resp.data)
        print(f"  POST /api/rules/reload -> {reload_data['message']}")
        print(f"    活跃规则: {reload_data['active_rules']}, 活跃域名: {reload_data['active_domains']}")

        # ===== 测试 5: 域名 API 端点 =====
        print("\n--- 测试 5: 域名管理 API 端点 ---")

        resp = flask_client.get('/api/domains')
        domains = json.loads(resp.data)
        print(f"  GET /api/domains -> {len(domains)} 条域名")

        resp = flask_client.post('/api/domains',
                                 data=json.dumps({
                                     'domain': 'api-test-evil.com',
                                     'severity': 'high',
                                     'description': 'API测试域名'
                                 }),
                                 content_type='application/json')
        assert resp.status_code == 201
        new_domain_data = json.loads(resp.data)
        domain_id = new_domain_data['id']
        print(f"  POST /api/domains -> 创建 ID={domain_id}")

        resp = flask_client.delete(f'/api/domains/{domain_id}')
        assert resp.status_code == 200
        print(f"  DELETE /api/domains/{domain_id} -> 删除成功")

        # ===== 测试 6: 完整扫描流程模拟 =====
        print("\n--- 测试 6: 完整扫描流程模拟 ---")

        flow_task_id = 'full-flow-mock-001'
        MOCK_TASK_IDS.append(flow_task_id)
        existing = ScanTask.query.get(flow_task_id)
        if existing:
            db.session.delete(existing)
            db.session.commit()

        flow_task = ScanTask(
            id=flow_task_id,
            skill_name='full-flow-skill',
            skill_version='2.0',
            file_path='/tmp/fake',
            task_status='running',
            progress=0
        )
        db.session.add(flow_task)
        db.session.commit()

        flow_client = socketio.test_client(app)
        flow_client.emit('join_task', {'task_id': flow_task_id})

        flow_stages = [
            (25, 'running'),
            (50, 'running'),
            (75, 'running'),
            (100, 'completed'),
        ]

        flow_received = []
        for pct, status in flow_stages:
            flow_task.progress = pct
            if status == 'completed':
                flow_task.task_status = 'completed'
                flow_task.risk_level = 'warning'
                flow_task.risk_score = 35
                flow_task.threat_count = 2
            db.session.commit()

            emit_scan_progress(socketio, flow_task_id, pct, status,
                             risk_level=flow_task.risk_level if status == 'completed' else None)

            time.sleep(0.1)
            events = flow_client.get_received()
            for ev in events:
                if ev.get('name') == 'scan_progress':
                    data = ev.get('args', [{}])[0]
                    flow_received.append(data)

        flow_client.disconnect()

        print(f"  流程模拟收到 {len(flow_received)} 个进度事件")
        final = flow_received[-1] if flow_received else {}
        print(f"  最终: progress={final.get('progress')}%, status={final.get('status')}, risk_level={final.get('risk_level')}")

        if len(flow_received) >= 3 and final.get('status') == 'completed':
            print("  [✅ 通过] 完整扫描流程模拟正常")
        else:
            print("  [❌ 失败] 流程模拟异常")

    finally:
        cleanup_mock_tasks()

print("\n" + "=" * 60)
print("所有 Mock 测试完成！")
print("=" * 60)
