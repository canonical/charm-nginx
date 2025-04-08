#!/usr/bin/env python3
# Copyright 2020-2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Nginx charm."""

import logging
import os
import subprocess
from base64 import b64decode
from os.path import islink
from pathlib import Path

from jinja2 import Template
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

from utils import atomic_write_root_file

logger = logging.getLogger(__name__)
SSL_FOLDER_PATH = "/etc/nginx/ssl"
CA_CERT_PATH = "/usr/local/share/ca-certificates/nginx-server.crt"
SSL_CERT_PATH = "/etc/nginx/ssl/server.crt"
SSL_KEY_PATH = "/etc/nginx/ssl/server.key"


class NginxCharm(CharmBase):
    """Nginx operator charm class."""

    _stored = StoredState()

    def __init__(self, *args):  # noqa: D107
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.update_status, self._on_update_status)
        self.framework.observe(self.on.publish_relation_changed, self._on_publish_relation_changed)
        self.framework.observe(
            self.on.publish_relation_departed, self._on_publish_relation_departed
        )
        self._stored.set_default(config={"publishes": {}})

    def _on_update_status(self, _):
        try:
            subprocess.check_call(["service", "nginx", "status"])
            self.model.unit.status = ActiveStatus("Nginx is running")
        except subprocess.CalledProcessError:
            self.model.unit.status = BlockedStatus("Nginx is not running")

    def _on_install(self, _):
        subprocess.check_output(["apt", "install", "-y", "nginx"])
        subprocess.check_output(["service", "nginx", "stop"])
        os.remove("/etc/nginx/nginx.conf")
        os.unlink("/etc/nginx/sites-enabled/default")

        os.makedirs(SSL_FOLDER_PATH, 0o755, exist_ok=True)
        os.chown(SSL_FOLDER_PATH, 0, 0)
        os.chmod(SSL_FOLDER_PATH, 0o755)

    def _on_publish_relation_departed(self, event):
        if event.app.name in self._stored.config["publishes"]:
            self._stored.config["publishes"].pop(event.app.name, None)
            self._render_config(self._stored.config)
            self._reload_config()

    def _on_publish_relation_changed(self, event):
        relation_data = event.relation.data[event.unit]
        if "path" not in relation_data:
            logger.info("Relation with %s not ready", event.unit)
            return
        if "publishes" not in self._stored.config:
            self._stored.config["publishes"] = {}
        self._stored.config["publishes"][event.app.name] = relation_data["path"]
        self._render_config(self._stored.config)
        self._reload_config()

    def _on_config_changed(self, _):
        config = self.model.config
        for key in config:
            self._stored.config[key] = config[key]

        ssl_cert_path = Path(SSL_CERT_PATH)
        ssl_key_path = Path(SSL_KEY_PATH)
        ca_cert_path = Path(CA_CERT_PATH)

        if config.get("ssl_cert") and config.get("ssl_key"):
            atomic_write_root_file(SSL_CERT_PATH, b64decode(config["ssl_cert"]), 0o640)
            atomic_write_root_file(SSL_KEY_PATH, b64decode(config["ssl_key"]), 0o640)
        elif config.get("ssl_cert") or config.get("ssl_key"):
            self.model.unit.status = BlockedStatus("Both ssl_cert and ssl_key must be configured")
            return
        else:
            ssl_cert_path.unlink(missing_ok=True)
            ssl_key_path.unlink(missing_ok=True)

        if config.get("ssl_ca"):
            atomic_write_root_file(CA_CERT_PATH, b64decode(config["ssl_ca"]), 0o444)
        else:
            ca_cert_path.unlink(missing_ok=True)

        try:
            subprocess.check_call(["update-ca-certificates", "--fresh"])
        except subprocess.CalledProcessError:
            self.model.unit.status = BlockedStatus("Failed to update CA certificates")

        self._render_config(self._stored.config)
        self._reload_config()

    def _render_config(self, config):
        with open("templates/nginx.conf.j2", encoding="utf-8") as f:
            t = Template(f.read())
        with open("/etc/nginx/nginx.conf", "wb") as f:
            b = t.render(opts=config).encode("UTF-8")
            f.write(b)
        with open("templates/nginx-site.conf.j2", encoding="utf-8") as f:
            t = Template(f.read())
        site_conf_name = self.model.app.name
        with open(f"/etc/nginx/sites-available/{site_conf_name}", "wb") as f:
            b = t.render(config=config).encode("UTF-8")
            f.write(b)
        if not islink(f"/etc/nginx/sites-enabled/{site_conf_name}"):
            os.symlink(
                f"/etc/nginx/sites-available/{site_conf_name}",
                f"/etc/nginx/sites-enabled/{site_conf_name}",
            )

    def _reload_config(self):
        """Reload nginx service, starting it if it was not running.

        - Reload instead of restart to avoid downtime.
        - Use systemctl `reload-or-restart` instead of just `reload,`
          so that nginx will be started if it was not running
          (reload will fail if the service was not running).

        The function will raise `CalledProcessError` if reloading or starting fails.
        """
        subprocess.check_call(["systemctl", "reload-or-restart", "nginx"])


if __name__ == "__main__":  # pragma: nocover
    main(NginxCharm)
