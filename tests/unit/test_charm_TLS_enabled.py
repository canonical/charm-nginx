# Copyright 2020 Ubuntu
# See LICENSE file for licensing details.

import random
import subprocess
import unittest
from base64 import b64decode
from unittest.mock import MagicMock, Mock, patch
from uuid import uuid4

from ops.testing import Harness

from charm import NginxCharm, _create_path, _install_ca_cert, _write_file

SSL_CONFIG = {
    "host": str(uuid4()),
    "port": random.randint(10, 20),
    "ssl_cert": "dGVzdF9jZXJ0==",  # Padded base64 strings
    "ssl_key": "dGVzdF9rZXk=",  # Padded base64 strings
    "ssl_ca": "dGVzdF9jYV9jZXJ0==",
}
STORED_CONFIG = {"host": str(uuid4()), "port": random.randint(10, 20), "publishes": {}}


class TestCharmTLS(unittest.TestCase):
    @patch("charm._install_ca_cert")
    @patch("charm._write_file")
    def test_config_changed(
        self,
        mock_write_file,
        mock_install_ca_cert,
    ):
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
        mock_install_ca_cert.assert_called_with(b64decode("dGVzdF9jYV9jZXJ0"))


class TestUtil(unittest.TestCase):
    @patch("tempfile.NamedTemporaryFile")
    @patch("os.rename")
    @patch("os.fchmod")
    @patch("os.fchown")
    @patch("pwd.getpwnam")
    @patch("grp.getgrnam")
    def test_write_file(
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

        _write_file(path, content, perms)

        mock_tempfile_instance.write.assert_called_once_with(content)
        mock_tempfile_instance.flush.assert_called_once()

        mock_fchown.assert_called_once_with(
            mock_tempfile_instance.fileno(), mock_uid, mock_gid
        )
        mock_fchmod.assert_called_once_with(mock_tempfile_instance.fileno(), perms)

        mock_rename.assert_called_once_with(mock_tempfile_instance.name, path)

    @patch("subprocess.check_call")
    @patch("charm._write_file")
    def test_install_ca_cert(self, mock_write_file, mock_check_call):
        ca_cert = "test_cert"
        mock_check_call.side_effect = subprocess.CalledProcessError(
            1, "update-ca-certificates"
        )
        _install_ca_cert(ca_cert)
        mock_write_file.assert_called_once_with(
            "/usr/local/share/ca-certificates/nginx-server.crt", ca_cert, 0o444
        )
        mock_check_call.assert_called_once_with(["update-ca-certificates", "--fresh"])

    @patch("os.makedirs")
    @patch("os.chown")
    @patch("os.chmod")
    @patch("os.path.exists")
    def test_create_path(self, mock_path_exists, mock_chmod, mock_chown, mock_makedirs):
        mock_path_exists.return_value = False

        _create_path()
        mock_path_exists.assert_called_once_with("/etc/nginx/ssl")
        mock_makedirs.assert_called_once_with("/etc/nginx/ssl", 0o755)
        mock_chown.assert_called_once_with("/etc/nginx/ssl", 0, 0)
        mock_chmod.assert_called_once_with("/etc/nginx/ssl", 0o755)
