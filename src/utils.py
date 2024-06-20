import logging
import os
import tempfile

logger = logging.getLogger(__name__)
CA_CERT_PATH = "/usr/local/share/ca-certificates/nginx-server.crt"


def atomic_write_root_file(path: str, content: bytes, perms: int) -> None:
    """
    Create or overwrite a file with the contents of a byte string.

    :param str path: The file path where the content should be written.
    :param bytes content: The content to write to the file.
    :param int perms: The file permissions to set on the created file.
    """
    logger.debug(
        "Writing file {} with root ownership and permissions {:o}".format(path, perms)
    )

    # Create a temporary file and replace the target file
    # This ensures atomic file writing for safety
    dir_name = os.path.dirname(path)
    with tempfile.NamedTemporaryFile(dir=dir_name, delete=False) as tmp_file:
        tmp_file.write(content)
        tmp_file.flush()
        os.fchown(tmp_file.fileno(), 0, 0)
        os.fchmod(tmp_file.fileno(), perms)
        temp_path = tmp_file.name

    os.rename(temp_path, path)
