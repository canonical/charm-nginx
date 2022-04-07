#!/usr/bin/env python3
# Copyright 2020 Ubuntu
# See LICENSE file for licensing details.

import logging
import os
import subprocess
from os.path import islink

from jinja2 import Template
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

import pwd
import grp
import hashlib

from base64 import b64decode

logger = logging.getLogger(__name__)

def write_file(path, content, owner='root', group='root', perms=0o444):
    """Create or overwrite a file with the contents of a byte string."""
    uid = pwd.getpwnam(owner).pw_uid
    gid = grp.getgrnam(group).gr_gid
    # lets see if we can grab the file and compare the context, to avoid doing
    # a write.
    existing_content = None
    existing_uid, existing_gid, existing_perms = None, None, None
    try:
        with open(path, 'rb') as target:
            existing_content = target.read()
        stat = os.stat(path)
        existing_uid, existing_gid, existing_perms = (
            stat.st_uid, stat.st_gid, stat.st_mode
        )
    except Exception:
        pass
    if content != existing_content:
        logger.debug("Writing file {} {}:{} {:o}".format(path, owner, group, perms))
        with open(path, 'wb') as target:
            os.fchown(target.fileno(), uid, gid)
            os.fchmod(target.fileno(), perms)
            # if six.PY3 and isinstance(content, six.string_types):
            #     content = content.encode('UTF-8')
            target.write(content)
        return
    # the contents were the same, but we might still need to change the
    # ownership or permissions.
    if existing_uid != uid:
        logger.debug("Changing uid on already existing content: {} -> {}"
            .format(existing_uid, uid))
        os.chown(path, uid, -1)
    if existing_gid != gid:
        logger.debug("Changing gid on already existing content: {} -> {}"
            .format(existing_gid, gid))
        os.chown(path, -1, gid)
    if existing_perms != perms:
        logger.debug("Changing permissions on existing content: {} -> {}"
            .format(existing_perms, perms))
        os.chmod(path, perms)


def install_ca_cert(ca_cert, name=None):
    """
    Install the given cert as a trusted CA.

    The ``name`` is the stem of the filename where the cert is written, and if
    not provided, it will default to ``juju-{charm_name}``.

    If the cert is empty or None, or is unchanged, nothing is done.
    """
    if not ca_cert:
        return
    if not isinstance(ca_cert, bytes):
        ca_cert = ca_cert.encode('utf8')
    # if not name:
    #     name = 'juju-{}'.format(charm_name())
    cert_file = '/usr/local/share/ca-certificates/{}.crt'.format(name)
    new_hash = hashlib.md5(ca_cert).hexdigest()
    if file_hash(cert_file) == new_hash:
        return
    logger.info("Installing new CA cert at: {}".format(cert_file))
    write_file(cert_file, ca_cert)
    subprocess.check_call(['update-ca-certificates', '--fresh'])


def file_hash(path, hash_type='md5'):
    """Generate a hash checksum of the contents of 'path' or None if not found.

    :param str hash_type: Any hash alrgorithm supported by :mod:`hashlib`,
                        such as md5, sha1, sha256, sha512, etc.
    """
    if os.path.exists(path):
        h = getattr(hashlib, hash_type)()
        with open(path, 'rb') as source:
            h.update(source.read())
        return h.hexdigest()
    else:
        return None


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
        for key in self.model.config:
            if key not in self._stored.config:
                value = self.model.config[key]
                self._stored.config[key] = value
            if self.model.config[key] != self._stored.config[key]:
                value = self.model.config[key]
                logger.info("Setting {} to: {}".format(key, value))
                self._stored.config[key] = value

        # this should go into install hook
        uid = pwd.getpwnam('root').pw_uid
        gid = grp.getgrnam('root').gr_gid

        path = '/etc/nginx/ssl'
        if not os.path.exists(path):
            os.makedirs(path, 0o755)
            os.chown(path, uid, gid)
            os.chmod(path, 0o755)

        config = self._stored.config
        self._stored.config['ssl_enabled'] = ('ssl_cert' in config.keys() and 
            'ssl_key' in config.keys() and self._stored.config['ssl_cert'] and
            self._stored.config['ssl_key'])

        # write ssl certificate if present
        if 'ssl_cert' in config.keys() and self._stored.config['ssl_cert']:
            cert_path = os.path.join('/etc/nginx/ssl', 'server.crt')
            cert = b64decode(self._stored.config['ssl_cert'])
            write_file(cert_path, cert, 'root', 'root', 0o644)

        if 'ssl_key' in config.keys() and self._stored.config['ssl_key']:
            key_path = os.path.join('/etc/nginx/ssl', 'server.key')
            key = b64decode(self._stored.config['ssl_key'])
            write_file(key_path, key, 'root', 'root', 0o640)

        if 'ca_cert' in config.keys() and self._stored.config['ca_cert']:
            ca_cert = self._stored.config['ca_cert']
            install_ca_cert(b64decode(ca_cert), 'nginx-server.crt')


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
        subprocess.check_call(["service", "nginx", "restart"])


if __name__ == "__main__":
    main(NginxCharm)
