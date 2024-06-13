# Copyright 2020 Ubuntu
# See LICENSE file for licensing details.

import random
import subprocess
import unittest
from base64 import b64decode
from unittest.mock import MagicMock, Mock, patch
from uuid import uuid4

from ops.testing import Harness

from charm import NginxCharm
from utils import atomic_write_root_file, force_remove

SSL_CONFIG = {
    "host": str(uuid4()),
    "port": random.randint(10, 20),
    "ssl_cert": "dGVzdF9jZXJ0==",  # Padded base64 strings
    "ssl_key": "dGVzdF9rZXk=",  # Padded base64 strings
    "ssl_ca": "dGVzdF9jYV9jZXJ0==",
}
DEFAULT_CONFIG = {"host": str(uuid4()), "port": random.randint(10, 20)}
STORED_CONFIG = {"host": str(uuid4()), "port": random.randint(10, 20), "publishes": {}}


class TestCharmTLS(unittest.TestCase):
    @patch("subprocess.check_call")
    @patch("charm.atomic_write_root_file")
    def test_config_changed(self, mock_write_file, mock_check_call):
        mock_check_call.side_effect = subprocess.CalledProcessError(
            1, "update-ca-certificates"
        )
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.charm._render_config = Mock()
        harness.charm._reload_config = Mock()

        harness.update_config(SSL_CONFIG)

        mock_write_file.assert_any_call(
            "/etc/nginx/ssl/server.crt",
            b64decode("dGVzdF9jZXJ0=="),
            0o644,
        )
        mock_write_file.assert_any_call(
            "/etc/nginx/ssl/server.key",
            b64decode("dGVzdF9rZXk="),
            0o640,
        )

        mock_write_file.assert_any_call(
            "/usr/local/share/ca-certificates/nginx-server.crt",
            b64decode("dGVzdF9jYV9jZXJ0=="),
            0o444,
        )

        mock_check_call.assert_called_once_with(["update-ca-certificates", "--fresh"])

    @patch(
        "charm.os.path.exists",
        side_effect=lambda path: path
        in ["/etc/nginx/ssl/server.crt", "/etc/nginx/ssl/server.key"],
    )
    @patch("charm.force_remove")
    @patch("charm.atomic_write_root_file")
    def test_config_changed_remove_files(
        self, mock_write_file, mock_remove, mock_path_exists
    ):
        harness = Harness(NginxCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.charm._render_config = Mock()
        harness.charm._reload_config = Mock()

        # Update config without ssl_cert and ssl_key
        harness.update_config(DEFAULT_CONFIG)

        mock_remove.assert_any_call("/etc/nginx/ssl/server.crt")
        mock_remove.assert_any_call("/etc/nginx/ssl/server.key")
        mock_write_file.assert_not_called()


class TestUtil(unittest.TestCase):
    @patch("tempfile.NamedTemporaryFile")
    @patch("os.rename")
    @patch("os.fchmod")
    @patch("os.fchown")
    @patch("pwd.getpwnam")
    @patch("grp.getgrnam")
    def test_atomic_write_root_file(
        self,
        mock_getgrnam,
        mock_getpwnam,
        mock_fchown,
        mock_fchmod,
        mock_rename,
        mock_tempfile,
    ):
        mock_uid = 0
        mock_gid = 0
        mock_getpwnam.return_value = MagicMock(pw_uid=mock_uid)
        mock_getgrnam.return_value = MagicMock(gr_gid=mock_gid)

        mock_tempfile_instance = MagicMock()
        mock_tempfile.return_value.__enter__.return_value = mock_tempfile_instance
        mock_tempfile_instance.name = "/tmp/tmpfile"
        mock_tempfile_instance.fileno.return_value = 3

        path = "/tmp/testfile"
        content = b"test content"
        perms = 0o644

        atomic_write_root_file(path, content, perms)

        mock_tempfile_instance.write.assert_called_once_with(content)
        mock_tempfile_instance.flush.assert_called_once()

        mock_fchown.assert_called_once_with(
            mock_tempfile_instance.fileno(), mock_uid, mock_gid
        )
        mock_fchmod.assert_called_once_with(mock_tempfile_instance.fileno(), perms)

        mock_rename.assert_called_once_with(mock_tempfile_instance.name, path)
