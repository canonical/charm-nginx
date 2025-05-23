# Copyright 2020 Ubuntu
# See LICENSE file for licensing details.

import random
import subprocess
import unittest
from unittest.mock import Mock, call, mock_open, patch
from uuid import uuid4

from jinja2 import Template
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import NginxCharm

DEFAULT_CONFIG = {"host": str(uuid4()), "port": random.randint(10, 20)}
STORED_CONFIG = {"host": str(uuid4()), "port": random.randint(10, 20), "publishes": {}}


class TestCharm(unittest.TestCase):
    @patch("subprocess.check_call", side_effect=subprocess.CalledProcessError(0, ""))
    def test_config_changed(self, mock_subproc):
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.charm._render_config = Mock()
        harness.charm._reload_config = Mock()
        harness.update_config(DEFAULT_CONFIG)
        default_config = {**DEFAULT_CONFIG, "publishes": {}}
        self.assertEqual(harness.charm._stored.config, default_config)
        self.assertTrue(harness.charm._render_config.called)
        self.assertTrue(harness.charm._reload_config.called)
        assert mock_subproc.call_args == call(["update-ca-certificates", "--fresh"])
        assert harness.model.unit.status == BlockedStatus("Failed to update CA certificates")

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

    @patch("os.makedirs")
    @patch("os.chown")
    @patch("os.chmod")
    @patch("os.path.exists")
    @patch("os.unlink")
    @patch("os.remove")
    @patch("subprocess.check_output")
    def test_install(
        self,
        mock_subproc,
        os_remove,
        os_unlink,
        mock_path_exists,
        mock_chmod,
        mock_chown,
        mock_makedirs,
    ):
        mock_path_exists.return_value = False
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
        mock_makedirs.assert_called_once_with("/etc/nginx/ssl", 0o755, exist_ok=True)
        mock_chown.assert_called_once_with("/etc/nginx/ssl", 0, 0)
        mock_chmod.assert_called_once_with("/etc/nginx/ssl", 0o755)

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
        assert mock_subproc.call_args == call(["systemctl", "reload-or-restart", "nginx"])

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
        assert mock_open_call.call_args_list[0] == call(
            "templates/nginx.conf.j2", encoding="utf-8"
        )
        assert mock_open_call.call_args_list[1] == call("/etc/nginx/nginx.conf", "wb")
        assert mock_open_call.call_args_list[2] == call(
            "templates/nginx-site.conf.j2", encoding="utf-8"
        )
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
