import grp
import logging
import os
import pwd
import subprocess
import tempfile

logger = logging.getLogger(__name__)
CA_CERT_PATH = "/usr/local/share/ca-certificates/{}.crt".format("nginx-server")


class CAInstallError(Exception):
    """Custom exception for CA certificate installation errors."""


def write_file(path: str, content: bytes, perms: int) -> None:
    """
    Create or overwrite a file with the contents of a byte string.

    :param str path: The file path where the content should be written.
    :param bytes content: The content to write to the file.
    :param int perms: The file permissions to set on the created file.
    """
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("root").gr_gid

    logger.debug(
        "Writing file {} with root ownership and permissions {:o}".format(path, perms)
    )

    # Create a temporary file and replace the target file
    # This ensures atomic file writing for safety
    dir_name = os.path.dirname(path)
    with tempfile.NamedTemporaryFile(dir=dir_name, delete=False) as tmp_file:
        tmp_file.write(content)
        tmp_file.flush()
        os.fchown(tmp_file.fileno(), uid, gid)
        os.fchmod(tmp_file.fileno(), perms)
        temp_path = tmp_file.name

    os.rename(temp_path, path)


def install_ca_cert(ca_cert: bytes):
    """
    Install the given cert as a trusted CA.

    :param bytes ca_cert: The base64 decoded CA certificate.
    """
    cert_file = CA_CERT_PATH
    logger.info("Installing new CA cert at: %s", cert_file)
    write_file(cert_file, ca_cert, 0o444)

    # Execute the command to update the CA certificates
    try:
        subprocess.check_call(["update-ca-certificates", "--fresh"])
    except subprocess.CalledProcessError as error:
        raise CAInstallError("Failed to update CA certificates") from error


def create_path():
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("root").gr_gid

    path = "/etc/nginx/ssl"
    if not os.path.exists(path):
        os.makedirs(path, 0o755)
        os.chown(path, uid, gid)
        os.chmod(path, 0o755)
