# Copyright 2020 Ubuntu
# See LICENSE file for licensing details.

import hashlib
import random
import subprocess
import unittest
from base64 import b64decode
from unittest.mock import Mock, call, mock_open, patch
from uuid import uuid4

from jinja2 import Template
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import NginxCharm, file_hash, install_ca_cert, write_file

DEFAULT_CONFIG = {
    "host": str(uuid4()),
    "port": random.randint(10, 20),
    "ssl_cert": "dGVzdF9jZXJ0==",  # Padded base64 strings
    "ssl_key": "dGVzdF9rZXk=",  # Padded base64 strings
    "ca_cert": "dGVzdF9jYV9jZXJ0==",
}
NEW_CONFIG = {
    "host": str(uuid4()),
    "port": random.randint(10, 20),
    "ssl_cert": "dGVzdF9jZXJ0==",  # Padded base64 strings
    "ssl_key": "dGVzdF9rZXk=",  # Padded base64 strings
    "ca_cert": "dGVzdF9jYV9jZXJ0==",
}
STORED_CONFIG = {"host": str(uuid4()), "port": random.randint(10, 20), "publishes": {}}


class TestCharm(unittest.TestCase):
    @patch("charm.install_ca_cert")
    @patch("charm.write_file")
    @patch("os.path.exists", return_value=False)
    @patch("os.makedirs")
    @patch("os.chown")
    @patch("os.chmod")
    @patch("subprocess.check_call")
    def test_config_changed(
        self,
        mock_check_call,
        mock_chmod,
        mock_chown,
        mock_makedirs,
        mock_path_exists,
        mock_write_file,
        mock_install_ca_cert,
    ):
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.charm._render_config = Mock()
        harness.charm._reload_config = Mock()
        harness.update_config(DEFAULT_CONFIG)
        harness.update_config(NEW_CONFIG)
        default_config = {**NEW_CONFIG, "publishes": {}, "ssl_enabled": True}
        print("actual config:", harness.charm._stored.config)
        print("expected config:", default_config)
        self.assertEqual(harness.charm._stored.config, default_config)
        self.assertTrue(harness.charm._render_config.called)
        self.assertTrue(harness.charm._reload_config.called)
        mock_makedirs.assert_called_with("/etc/nginx/ssl", 0o755)
        mock_chown.assert_called_with("/etc/nginx/ssl", 0, 0)
        mock_chmod.assert_called_with("/etc/nginx/ssl", 0o755)
        mock_write_file.assert_any_call(
            "/etc/nginx/ssl/server.crt",
            b64decode("dGVzdF9jZXJ0=="),
            "root",
            "root",
            0o644,
        )
        mock_write_file.assert_any_call(
            "/etc/nginx/ssl/server.key",
            b64decode("dGVzdF9rZXk="),
            "root",
            "root",
            0o640,
        )
        mock_install_ca_cert.assert_called_with(
            b64decode("dGVzdF9jYV9jZXJ0"), "nginx-server.crt"
        )

    def test_publish_relation_joined(self):
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.charm._render_config = Mock()
        harness.charm._reload_config = Mock()
        app_name = "publisher"
        peer = "{}/{}".format(app_name, random.randint(2, 100))
        relation_id = harness.add_relation("publish", "publisher")
        harness.add_relation_unit(relation_id, peer)
        path = str(uuid4())
        harness.update_relation_data(relation_id, peer, {"path": path})
        assert harness.get_relation_data(relation_id, peer) == {"path": path}
        self.assertTrue(harness.charm._render_config.called)
        self.assertTrue(harness.charm._reload_config.called)

    def test_publish_relation_departed(self):
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.charm._render_config = Mock()
        harness.charm._reload_config = Mock()
        publish1 = str(uuid4())
        app_name = str(uuid4())
        harness.charm._stored.config = {
            "publishes": {
                publish1: publish1,
                app_name: app_name,
            }
        }
        action_event = Mock()
        action_event.app.name = app_name
        harness.charm._on_publish_relation_departed(action_event)
        self.assertTrue(harness.charm._render_config.called)
        self.assertTrue(harness.charm._reload_config.called)

    def test_publish_relation_changed_no_path(self):
        harness = Harness(NginxCharm)
        harness.begin()
        harness.charm._render_config = Mock()
        harness.charm._reload_config = Mock()
        app_name = "publisher"
        peer = "{}/{}".format(app_name, random.randint(2, 100))
        relation_id = harness.add_relation("publish", "publisher")
        harness.add_relation_unit(relation_id, peer)
        harness.update_relation_data(relation_id, peer, {"nopath": ""})
        self.assertFalse(harness.charm._render_config.called)
        self.assertFalse(harness.charm._reload_config.called)

    def test_publish_relation_changed_no_publishes(self):
        harness = Harness(NginxCharm)
        harness.begin()
        harness.charm._render_config = Mock()
        harness.charm._reload_config = Mock()
        if "publishes" in harness.charm._stored.config:
            del harness.charm._stored.config["publishes"]
        app_name = "publisher"
        peer = "{}/{}".format(app_name, random.randint(2, 100))
        relation_id = harness.add_relation("publish", "publisher")
        harness.add_relation_unit(relation_id, peer)
        path = str(uuid4())
        harness.update_relation_data(relation_id, peer, {"path": path})
        self.assertIn("publishes", harness.charm._stored.config)
        self.assertIn(app_name, harness.charm._stored.config["publishes"])
        self.assertEqual(harness.charm._stored.config["publishes"][app_name], path)
        self.assertTrue(harness.charm._render_config.called)
        self.assertTrue(harness.charm._reload_config.called)

    @patch("os.unlink")
    @patch("os.remove")
    @patch("subprocess.check_output")
    def test_install(self, mock_subproc, os_remove, os_unlink):
        process_mock = Mock()
        mock_subproc.return_value = process_mock
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        action_event = Mock()
        harness.charm._on_install(action_event)
        self.assertTrue(mock_subproc.called)
        self.assertTrue(os_remove.called)
        self.assertTrue(os_unlink.called)
        assert mock_subproc.call_args_list[0] == call(["apt", "install", "-y", "nginx"])
        assert mock_subproc.call_args_list[1] == call(["service", "nginx", "stop"])

    @patch("subprocess.check_call")
    def test_update_status_running(self, mock_subproc):
        process_mock = Mock()
        mock_subproc.return_value = process_mock
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        action_event = Mock()
        harness.charm._on_update_status(action_event)
        self.assertTrue(mock_subproc.called)
        assert mock_subproc.call_args == call(["service", "nginx", "status"])
        assert harness.model.unit.status == ActiveStatus("Nginx is running")

    @patch("subprocess.check_call", side_effect=subprocess.CalledProcessError(0, ""))
    def test_update_status_stopped(self, mock_subproc):
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        action_event = Mock()
        harness.charm._on_update_status(action_event)
        self.assertTrue(mock_subproc.called)
        assert mock_subproc.call_args == call(["service", "nginx", "status"])
        assert harness.model.unit.status == BlockedStatus("Nginx is not running")

    @patch("subprocess.check_call")
    def test_reload_config(self, mock_subproc):
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.charm._reload_config()
        assert mock_subproc.call_args == call(["service", "nginx", "restart"])

    @patch("charm.islink")
    @patch("os.symlink")
    @patch("subprocess.check_call")
    def test_render_config(self, mock_subproc, os_symlink, os_path_islink):
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        config = {}
        os_path_islink.return_value = False
        with patch("builtins.open", mock_open()) as mock_open_call:
            harness.charm._render_config(config)
        assert mock_open_call.call_args_list[0] == call("templates/nginx.conf.j2")
        assert mock_open_call.call_args_list[1] == call("/etc/nginx/nginx.conf", "wb")
        assert mock_open_call.call_args_list[2] == call("templates/nginx-site.conf.j2")
        assert mock_open_call.call_args_list[3] == call(
            "/etc/nginx/sites-available/{}".format(harness.model.app.name), "wb"
        )
        assert os_symlink.call_args == call(
            "/etc/nginx/sites-available/{}".format(harness.model.app.name),
            "/etc/nginx/sites-enabled/{}".format(harness.model.app.name),
        )

    def test_template_nginx_conf(self):
        with open("templates/nginx.conf.j2") as f:
            t = Template(f.read())
        t.render(config=STORED_CONFIG).encode("UTF-8")

    def test_template_nginx_site_no_publish_conf(self):
        with open("templates/nginx-site.conf.j2") as f:
            t = Template(f.read())
        t.render(config=STORED_CONFIG).encode("UTF-8")

    def test_template_nginx_site_publishes_conf(self):
        config = STORED_CONFIG
        config["publishes"] = {str(uuid4()): str(uuid4())}
        with open("templates/nginx-site.conf.j2") as f:
            t = Template(f.read())
        t.render(config=config).encode("UTF-8")


class TestUtil(unittest.TestCase):
    @patch("os.fchmod")
    @patch("os.fchown")
    @patch("os.chown")
    @patch("os.chmod")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.path.exists", return_value=False)
    @patch("pwd.getpwnam")
    @patch("grp.getgrnam")
    def test_write_file(
        self,
        mock_getgrnam,
        mock_getpwnam,
        mock_exists,
        mock_open,
        mock_chmod,
        mock_chown,
        mock_fchown,
        mock_fchmod,
    ):
        write_file(
            "/tmp/testfile",
            b"test content",
            owner="testuser",
            group="testgroup",
            perms=0o644,
        )
        mock_getpwnam.assert_called_with("testuser")
        mock_getgrnam.assert_called_with("testgroup")
        mock_open.assert_called_with("/tmp/testfile", "wb")

    @patch("os.fchmod")
    @patch("os.fchown")
    @patch("os.chown")
    @patch("os.chmod")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.stat")
    @patch("pwd.getpwnam")
    @patch("grp.getgrnam")
    def test_write_file_existing_file_same_content(
        self,
        mock_getgrnam,
        mock_getpwnam,
        mock_stat,
        mock_open,
        mock_chmod,
        mock_chown,
        mock_fchown,
        mock_fchmod,
    ):
        mock_getpwnam.return_value.pw_uid = 1001
        mock_getgrnam.return_value.gr_gid = 1001

        stat_result = unittest.mock.Mock()
        stat_result.st_uid = 1002
        stat_result.st_gid = 1002
        stat_result.st_mode = 0o640
        mock_stat.return_value = stat_result

        mock_open().read.return_value = b"test content"

        write_file(
            "/tmp/testfile",
            b"test content",
            owner="testuser",
            group="testgroup",
            perms=0o644,
        )

        mock_getpwnam.assert_called_with("testuser")
        mock_getgrnam.assert_called_with("testgroup")
        mock_open.assert_called_with("/tmp/testfile", "rb")
        mock_chown.assert_called_with("/tmp/testfile", -1, 1001)
        mock_chmod.assert_called_with("/tmp/testfile", 0o644)

    @patch("charm.file_hash", return_value="oldhash")
    @patch("subprocess.check_call")
    @patch("charm.write_file")
    def test_install_ca_cert(self, mock_write_file, mock_check_call, mock_file_hash):
        ca_cert = "test_cert"
        install_ca_cert(ca_cert, "testname")
        mock_write_file.assert_called()
        mock_check_call.assert_called_with(["update-ca-certificates", "--fresh"])

    @patch("subprocess.check_call")
    @patch("charm.write_file")
    @patch("charm.file_hash")
    def test_install_ca_cert_none(
        self, mock_file_hash, mock_write_file, mock_check_call
    ):
        install_ca_cert(None)
        mock_write_file.assert_not_called()
        mock_check_call.assert_not_called()

    @patch("subprocess.check_call")
    @patch("charm.write_file")
    @patch("charm.file_hash")
    def test_install_ca_cert_same_hash(
        self, mock_file_hash, mock_write_file, mock_check_call
    ):
        ca_cert = "test_cert"
        mock_file_hash.return_value = hashlib.md5(ca_cert.encode("utf8")).hexdigest()

        install_ca_cert(ca_cert, "testname")

        mock_write_file.assert_not_called()
        mock_check_call.assert_not_called()

    @patch("os.path.exists", return_value=True)
    @patch("hashlib.md5")
    @patch("builtins.open", new_callable=mock_open, read_data=b"test content")
    def test_file_hash(self, mock_open, mock_md5, mock_exists):
        mock_hash = Mock()
        mock_md5.return_value = mock_hash
        mock_hash.hexdigest.return_value = "testhash"

        result = file_hash("/tmp/testfile")

        self.assertEqual(result, "testhash")
        mock_open.assert_called_with("/tmp/testfile", "rb")
        mock_hash.update.assert_called_with(b"test content")
        mock_hash.hexdigest.assert_called_once()

    @patch("os.path.exists", return_value=False)
    def test_file_hash_not_exists(self, mock_exists):
        result = file_hash("/tmp/nonexistentfile")
        self.assertIsNone(result)
        mock_exists.assert_called_with("/tmp/nonexistentfile")
