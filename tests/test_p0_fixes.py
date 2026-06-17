import os
import sys
import zipfile
import tarfile
import tempfile
import shutil
import json
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.routes import _safe_extract_zip, _safe_extract_tar


class TestSafeExtractZip:
    """P0-1 修复验证：_safe_extract_zip 防止 Zip Slip 路径穿越"""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_zip(self, entries, zip_name="test.zip"):
        zip_path = os.path.join(self.tmpdir, zip_name)
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for name, content in entries:
                zf.writestr(name, content)
        return zip_path

    def test_normal_zip_extracts_all(self):
        zip_path = self._create_zip([
            ("hello.txt", "hello world"),
            ("subdir/nested.txt", "nested content"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_normal")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_zip(zip_path, extract_dir)

        assert skipped == []
        assert os.path.isfile(os.path.join(extract_dir, "hello.txt"))
        assert os.path.isfile(os.path.join(extract_dir, "subdir", "nested.txt"))
        with open(os.path.join(extract_dir, "hello.txt")) as f:
            assert f.read() == "hello world"

    def test_zip_slip_absolute_path_blocked(self):
        zip_path = self._create_zip([
            ("../../../etc/passwd", "root:x:0:0"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_abs")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_zip(zip_path, extract_dir)

        assert len(skipped) == 1
        assert "../../../etc/passwd" in skipped
        assert not os.path.exists(os.path.join(self.tmpdir, "etc", "passwd"))

    def test_zip_slip_dotdot_traversal_blocked(self):
        zip_path = self._create_zip([
            ("../../secret.txt", "stolen data"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_dotdot")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_zip(zip_path, extract_dir)

        assert len(skipped) == 1
        assert not os.path.exists(os.path.join(self.tmpdir, "secret.txt"))

    def test_mixed_normal_and_malicious_entries(self):
        zip_path = self._create_zip([
            ("good.txt", "safe content"),
            ("../../evil.txt", "evil content"),
            ("also_good.txt", "also safe"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_mixed")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_zip(zip_path, extract_dir)

        assert len(skipped) == 1
        assert "../../evil.txt" in skipped
        assert os.path.isfile(os.path.join(extract_dir, "good.txt"))
        assert os.path.isfile(os.path.join(extract_dir, "also_good.txt"))

    def test_directory_entry_created(self):
        zip_path = self._create_zip([
            ("mydir/", ""),
            ("mydir/file.txt", "inside dir"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_dir")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_zip(zip_path, extract_dir)

        assert skipped == []
        assert os.path.isdir(os.path.join(extract_dir, "mydir"))
        assert os.path.isfile(os.path.join(extract_dir, "mydir", "file.txt"))


class TestSafeExtractTar:
    """P0-1 修复验证：_safe_extract_tar 防止 Tar Slip 路径穿越"""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_tar(self, entries, tar_name="test.tar.gz"):
        tar_path = os.path.join(self.tmpdir, tar_name)
        with tarfile.open(tar_path, 'w:gz') as tf:
            for name, content in entries:
                info = tarfile.TarInfo(name=name)
                info.size = len(content.encode())
                import io
                tf.addfile(info, io.BytesIO(content.encode()))
        return tar_path

    def test_normal_tar_extracts_all(self):
        tar_path = self._create_tar([
            ("hello.txt", "hello world"),
            ("subdir/nested.txt", "nested content"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_normal")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_tar(tar_path, extract_dir)

        assert skipped == []
        assert os.path.isfile(os.path.join(extract_dir, "hello.txt"))
        assert os.path.isfile(os.path.join(extract_dir, "subdir", "nested.txt"))

    def test_tar_slip_absolute_path_blocked(self):
        tar_path = self._create_tar([
            ("../../../etc/passwd", "root:x:0:0"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_abs")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_tar(tar_path, extract_dir)

        assert len(skipped) == 1
        assert not os.path.exists(os.path.join(self.tmpdir, "etc", "passwd"))

    def test_tar_slip_dotdot_traversal_blocked(self):
        tar_path = self._create_tar([
            ("../../secret.txt", "stolen data"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_dotdot")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_tar(tar_path, extract_dir)

        assert len(skipped) == 1
        assert not os.path.exists(os.path.join(self.tmpdir, "secret.txt"))

    def test_symlink_entry_blocked(self):
        tar_path = os.path.join(self.tmpdir, "symlink.tar.gz")
        with tarfile.open(tar_path, 'w:gz') as tf:
            link_info = tarfile.TarInfo(name="link_to_etc")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "/etc/passwd"
            tf.addfile(link_info)
        extract_dir = os.path.join(self.tmpdir, "out_symlink")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_tar(tar_path, extract_dir)

        assert len(skipped) == 1
        assert "link_to_etc" in skipped
        assert not os.path.exists(os.path.join(extract_dir, "link_to_etc"))

    def test_hardlink_entry_blocked(self):
        tar_path = os.path.join(self.tmpdir, "hardlink.tar.gz")
        with tarfile.open(tar_path, 'w:gz') as tf:
            link_info = tarfile.TarInfo(name="hardlink_file")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "/etc/shadow"
            tf.addfile(link_info)
        extract_dir = os.path.join(self.tmpdir, "out_hardlink")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_tar(tar_path, extract_dir)

        assert len(skipped) == 1
        assert "hardlink_file" in skipped

    def test_mixed_normal_and_malicious_tar(self):
        tar_path = self._create_tar([
            ("good.txt", "good content"),
            ("../../evil.txt", "evil content"),
        ])
        extract_dir = os.path.join(self.tmpdir, "out_mixed")
        os.makedirs(extract_dir, exist_ok=True)

        skipped = _safe_extract_tar(tar_path, extract_dir)

        assert len(skipped) == 1
        assert os.path.isfile(os.path.join(extract_dir, "good.txt"))
        assert not os.path.exists(os.path.join(self.tmpdir, "evil.txt"))


class TestScanOptions:
    """扫描选项控制各维度是否执行"""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.skill_dir = os.path.join(self.tmpdir, "skill")
        os.makedirs(self.skill_dir)
        with open(os.path.join(self.skill_dir, "manifest.json"), "w") as f:
            json.dump({"name": "test-skill", "version": "1.0"}, f)
        with open(os.path.join(self.skill_dir, "main.py"), "w") as f:
            f.write("import os\nos.system('rm -rf /')\napi_key = 'sk-123456'\n")

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_scanner(self):
        from app.scanner.engine import SecurityScanner
        task = MagicMock()
        task.id = "test-task-id"
        task.skill_name = "test-skill"
        rules = []
        return SecurityScanner(task, rules)

    def test_default_options_runs_all_dimensions(self):
        scanner = self._make_scanner()
        with patch.object(scanner, '_static_analysis') as sa, \
             patch.object(scanner, '_signature_matching') as sm, \
             patch.object(scanner, '_sandbox_analysis') as ba:
            scanner.scan_skill(self.skill_dir)
            sa.assert_called_once()
            sm.assert_called_once()
            ba.assert_called_once()

    def test_none_options_runs_all_dimensions(self):
        scanner = self._make_scanner()
        with patch.object(scanner, '_static_analysis') as sa, \
             patch.object(scanner, '_signature_matching') as sm, \
             patch.object(scanner, '_sandbox_analysis') as ba:
            scanner.scan_skill(self.skill_dir, scan_options=None)
            sa.assert_called_once()
            sm.assert_called_once()
            ba.assert_called_once()

    def test_disable_static_analysis(self):
        scanner = self._make_scanner()
        opts = {'static_analysis': False, 'signature_matching': True, 'sandbox': True}
        with patch.object(scanner, '_static_analysis') as sa, \
             patch.object(scanner, '_signature_matching') as sm, \
             patch.object(scanner, '_sandbox_analysis') as ba:
            scanner.scan_skill(self.skill_dir, scan_options=opts)
            sa.assert_not_called()
            sm.assert_called_once()
            ba.assert_called_once()

    def test_disable_sandbox_analysis(self):
        scanner = self._make_scanner()
        opts = {'static_analysis': True, 'signature_matching': True, 'sandbox': False}
        with patch.object(scanner, '_static_analysis') as sa, \
             patch.object(scanner, '_signature_matching') as sm, \
             patch.object(scanner, '_sandbox_analysis') as ba:
            scanner.scan_skill(self.skill_dir, scan_options=opts)
            sa.assert_called_once()
            sm.assert_called_once()
            ba.assert_not_called()

    def test_disable_signature_matching(self):
        scanner = self._make_scanner()
        opts = {'static_analysis': True, 'signature_matching': False, 'sandbox': True}
        with patch.object(scanner, '_static_analysis') as sa, \
             patch.object(scanner, '_signature_matching') as sm, \
             patch.object(scanner, '_sandbox_analysis') as ba:
            scanner.scan_skill(self.skill_dir, scan_options=opts)
            sa.assert_called_once()
            sm.assert_not_called()
            ba.assert_called_once()

    def test_only_static_analysis_enabled(self):
        scanner = self._make_scanner()
        opts = {'static_analysis': True, 'signature_matching': False, 'sandbox': False}
        with patch.object(scanner, '_static_analysis') as sa, \
             patch.object(scanner, '_signature_matching') as sm, \
             patch.object(scanner, '_sandbox_analysis') as ba:
            scanner.scan_skill(self.skill_dir, scan_options=opts)
            sa.assert_called_once()
            sm.assert_not_called()
            ba.assert_not_called()

    def test_single_file_scan_respects_options(self):
        from app.scanner.engine import SecurityScanner
        single_file = os.path.join(self.tmpdir, "single.md")
        with open(single_file, "w") as f:
            f.write("# Test Skill\nThis is a test.\n")

        task = MagicMock()
        task.id = "test-task-id"
        task.skill_name = "test-skill"
        rules = []
        scanner = SecurityScanner(task, rules)

        opts = {'static_analysis': True, 'signature_matching': True, 'sandbox': False}
        result = scanner.scan_skill(single_file, scan_options=opts)
        assert result['findings'] is not None
        assert isinstance(result['risk_score'], int)

    def test_scan_options_stored_in_task_model(self):
        from app.models import ScanTask
        task = ScanTask(
            skill_name="test",
            skill_version="1.0",
            file_path="/tmp/test",
            scan_options='{"static_analysis": true, "sandbox": false}'
        )
        parsed = json.loads(task.scan_options)
        assert parsed['static_analysis'] is True
        assert parsed['sandbox'] is False

    def test_scan_options_default_empty_dict(self):
        from app.models import ScanTask
        task = ScanTask(
            skill_name="test",
            skill_version="1.0",
            file_path="/tmp/test"
        )
        assert task.scan_options is None or task.scan_options == '{}'
