#!/usr/bin/env python3
# Copyright 2020 Ubuntu
# See LICENSE file for licensing details.

import logging
import os
import subprocess
from base64 import b64decode
from os.path import islink

from jinja2 import Template
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

from utils import CAInstallError, create_path, install_ca_cert, write_file

logger = logging.getLogger(__name__)


class NginxCharm(CharmBase):
    _stored = StoredState()

    def __init__(self, *args):  # noqa: D107
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.update_status, self._on_update_status)
        self.framework.observe(
            self.on.publish_relation_changed, self._on_publish_relation_changed
        )
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
        create_path()

    def _on_publish_relation_departed(self, event):
        if event.app.name in self._stored.config["publishes"]:
            self._stored.config["publishes"].pop(event.app.name, None)
            self._render_config(self._stored.config)
            self._reload_config()

    def _on_publish_relation_changed(self, event):
        relation_data = event.relation.data[event.unit]
        if "path" not in relation_data:
            logger.info("Relation with {} not ready".format(event.unit))
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

        try:
            if config.get("ssl_cert"):
                cert_path = os.path.join("/etc/nginx/ssl", "server.crt")
                cert = b64decode(config["ssl_cert"])
                write_file(cert_path, cert, 0o644)

            if config.get("ssl_key"):
                key_path = os.path.join("/etc/nginx/ssl", "server.key")
                key = b64decode(config["ssl_key"])
                write_file(key_path, key, 0o640)

            if config.get("ssl_ca"):
                ca_cert = config["ssl_ca"]
                install_ca_cert(b64decode(ca_cert))
        except CAInstallError as e:
            logger.error("CA installation error: %s", e)

        self._render_config(self._stored.config)
        self._reload_config()

    def _render_config(self, config):
        with open("templates/nginx.conf.j2") as f:
            t = Template(f.read())
        with open("/etc/nginx/nginx.conf", "wb") as f:
            b = t.render(opts=config).encode("UTF-8")
            f.write(b)
        with open("templates/nginx-site.conf.j2") as f:
            t = Template(f.read())
        site_conf_name = "{}".format(self.model.app.name)
        with open("/etc/nginx/sites-available/{}".format(site_conf_name), "wb") as f:
            b = t.render(config=config).encode("UTF-8")
            f.write(b)
        if not islink("/etc/nginx/sites-enabled/{}".format(site_conf_name)):
            os.symlink(
                "/etc/nginx/sites-available/{}".format(site_conf_name),
                "/etc/nginx/sites-enabled/{}".format(site_conf_name),
            )

    def _reload_config(self):
        subprocess.check_call(["service", "nginx", "reload"])


if __name__ == "__main__":  # pragma: nocover
    main(NginxCharm)
