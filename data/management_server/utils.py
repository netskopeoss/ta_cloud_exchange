"""Utility for the Management server and Setup script."""

import ipaddress
import fcntl
import logging
import logging.handlers
import os
import ssl
from pathlib import Path, PurePath
import re
import shutil
import subprocess
import sys
from secrets import token_bytes
from base64 import b64encode
import urllib
import urllib.request
import traceback

NODE_IP = ""
GLUSTERFS_BASE_PORT = 24009
GLUSTERFS_MAX_PORT = 24029
TOKEN_VALIDITY = 3600
API_PREFIX = "/api/management"
SECRET_FILE_NAME = ".env.keys"
RECOMMENDED_HOST_OS = ["Ubuntu 22", "Ubuntu 24", "RHEL 8", "RHEL 9"]
RECOMMENDED_HOST_OS_VERSION = ["Ubuntu 22.04", "Ubuntu 24.04", "RHEL 8.8", "RHEL 9.5"]
RECOMMENDED_UBUNTU_VERSION = ["22.04", "24.04"]
RECOMMENDED_RHEL_VERSION = ["8.8", "9.5"]
AVAILABLE_INPUTS = {}
SUDO_PREFIX = ""
UPDATES_ALLOWED_ON_ENV = [
    "HA_ENABLED",
    "HA_IP_LIST",
    "HA_NFS_DATA_DIRECTORY",
    "JWT_SECRET",
    "HA_PRIMARY_NODE_IP",
    "HA_CURRENT_NODE",
    "CORE_HTTPS_PROXY",
    "CORE_HTTP_PROXY",
]
CONFIG_FILE_PATH = "./cloudexchange.config"
LOG_FILE_BACKUP_COUNT = 5
LOG_FILE_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
KEYS_TO_REMOVE_IF_EMPTY = [
    "HA_ENABLED",
    "HA_CURRENT_NODE",
    "HA_NFS_DATA_DIRECTORY",
    "HA_IP_LIST",
    "HA_PRIMARY_NODE_IP",
    "GLUSTERFS_MAX_PORT",
    "GLUSTERFS_BASE_PORT",
]
CLOUD_EXCHANGE_CONFIG = {}
CLOUD_EXCHANGE_CONFIG_KEYS = {
    "MAINTENANCE_PASSWORD": {"type": str, "default": ""},
    "JWT_SECRET": {"type": str, "default": ""},
    "TLS_VERSION": {"type": str, "default": "1.3", "allowed_values": ["1.2", "1.3"]},
    "PROXY_URL": {"type": str, "default": ""},
    "PROXY_USERNAME": {"type": str, "default": ""},
    "PROXY_PASSWORD": {"type": str, "default": ""},
    "UI_PROTOCOL": {"type": str, "default": "https"},
    "UI_PORT": {"type": int, "default": 443},
    "CE_MANAGEMENT_PORT": {"type": int, "default": 8000},
    "HA_ENABLED": {"type": bool, "default": False},
    "HA_IP_LIST": {"type": str, "default": ""},
    "HA_NFS_DATA_DIRECTORY": {"type": str, "default": ""},
    "HA_CURRENT_NODE": {"type": str, "default": ""},
    "HA_PRIMARY_NODE_IP": {"type": str, "default": ""},
    "LOG_FILE_MAX_BYTES": {"type": int, "default": 10 * 1024 * 1024},
    "LOG_FILE_BACKUP_COUNT": {"type": int, "default": 5},
    "CE_SSL_CERTIFICATE_PASSWORD": {"type": str, "default": ""},
    "GLUSTERFS_BASE_PORT": {"type": int, "default": GLUSTERFS_BASE_PORT},
    "GLUSTERFS_MAX_PORT": {"type": int, "default": GLUSTERFS_MAX_PORT},
}
CA_CERTS_DIR = "./data/ca_certs/"

logger = logging.getLogger(__name__)


class ClientExceptions(Exception):
    """
    Base class for client exceptions.

    This class can be used to catch any exceptions
    that are raised by the client.
    """

    pass


class ServerExceptions(Exception):
    """
    Base class for server exceptions.

    This class can be used to catch any exceptions
    that are raised by the server.
    """

    pass


class SafeFormatter(logging.Formatter):
    """
    Logging formatter that ensures a 'node' attribute is always present in the log record.

    This formatter is used to guarantee that log messages always include a 'node' field, defaulting
    to 'localhost' if not present. This is useful for distributed or HA environments where logs
    should indicate the originating node.
    """

    def format(self, record):
        """
        Format the specified record, ensuring the 'node' attribute is present.

        Args:
            record (logging.LogRecord): The log record to be formatted.

        Returns:
            str: The formatted log message string, with a guaranteed 'node' field.
        """
        if "node" not in record.__dict__:
            record.__dict__["node"] = "localhost"
        return super().format(record)


def configure_logger(
    log_file_max_bytes,
    backup_count,
    logs_directory,
    log_file_name,
    should_add_stdout=True,
):
    """
    Configure the logger for management server.

    Args:
        log_file_max_bytes (int): The maximum size of the log file.
        backup_count (int): The number of backup log files to keep.
    """
    global logger  # noqa: F824
    logger.handlers.clear()

    logger.setLevel(logging.INFO)
    formatter = SafeFormatter("[%(asctime)s] [%(levelname)s] [%(node)s] %(message)s")
    if should_add_stdout:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    os.makedirs(logs_directory, exist_ok=True, mode=0o755)
    log_path = os.path.join(logs_directory, log_file_name)
    try:
        log_file_max_bytes = int(log_file_max_bytes)
    except (TypeError, ValueError):
        log_file_max_bytes = LOG_FILE_MAX_BYTES
    try:
        backup_count = int(backup_count)
    except (TypeError, ValueError):
        backup_count = LOG_FILE_BACKUP_COUNT

    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_path,
        maxBytes=log_file_max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def compare_versions(version1, version2):
    """Compare two versions for a package."""
    versions1 = [int(v) for v in version1.split(".")]
    versions2 = [int(v) for v in version2.split(".")]
    for i in range(max(len(versions1), len(versions2))):
        v1 = versions1[i] if i < len(versions1) else 0
        v2 = versions2[i] if i < len(versions2) else 0
        if v1 > v2:
            return True
        elif v1 < v2:
            return False
    return True
 

def get_os_name_and_major_version(handler):
    """
    Get the OS name and its major version.

    Args:
        handler (object): The BaseHTTPRequestHandler object.

    Returns:
        str: The OS name and its major version, separated by a space, e.g. "Ubuntu 20".

    Raises:
        Exception: If the OS name and version cannot be determined.
    """
    try:
        pretty_name = ""
        version_id = ""
        os_name = ""
        os_version = ""
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        pretty_name = line.split("=")[1].strip().strip('"')
                    elif line.startswith("VERSION_ID="):
                        version_id = line.split("=")[1].strip().strip('"')
                    if pretty_name and version_id:
                        break
            if "ubuntu" in pretty_name.lower():
                if version_id.split(".")[0] in ["20", "22", "24"]:
                    os_version = version_id.split(".")[0]
                os_name = "Ubuntu"
            elif "centos" in pretty_name.lower():
                if version_id.split(".")[0] in ["7", "8"]:
                    os_version = version_id.split(".")[0]
                os_name = "CentOS"
            elif "red hat" in pretty_name.lower():
                if version_id.split(".")[0] in ["7", "8", "9"]:
                    os_version = version_id.split(".")[0]
                os_name = "RHEL"

        os_name_and_major_version = f"{os_name} {os_version}".strip()
        if os_name_and_major_version not in RECOMMENDED_HOST_OS:
            write_chunk(
                handler.wfile,
                (
                    f"End: CE is not supported on {pretty_name}. "
                    f"Please switch to one of the supported version of OS. "
                    f"Supported OS: {RECOMMENDED_HOST_OS_VERSION}"
                ),
            )
            return "", ""
        elif "ubuntu" in pretty_name.lower():
            recommended_version = (
                RECOMMENDED_UBUNTU_VERSION[0]
                if version_id.split(".")[0] == "22"
                else RECOMMENDED_UBUNTU_VERSION[1]
            )
            if compare_versions(version_id, recommended_version):
                write_chunk(handler.wfile, f"Info: Ubuntu OS Version {version_id}")
            else:
                write_chunk(
                    handler.wfile,
                    f"End: Ubuntu OS Version {version_id} (Minimum {recommended_version} is required)"
                )
                return "", ""
            if version_id not in RECOMMENDED_UBUNTU_VERSION:
                write_chunk(
                    handler.wfile,
                    f"Warning: The recommended Ubuntu OS versions are {RECOMMENDED_UBUNTU_VERSION[0]} and {RECOMMENDED_UBUNTU_VERSION[1]}"
                )
        elif "red hat" in pretty_name.lower():
            recommended_version = (
                RECOMMENDED_RHEL_VERSION[0]
                if version_id.split(".")[0] == "8"
                else RECOMMENDED_RHEL_VERSION[1]
            )
            if compare_versions(version_id, recommended_version):
                write_chunk(handler.wfile, f"Info: RHEL OS Version {version_id}")
            else:
                write_chunk(
                    handler.wfile,
                    f"End: RHEL OS Version {version_id} (Minimum {recommended_version} is required)"
                )
                return "", ""
            if version_id not in RECOMMENDED_RHEL_VERSION:
                write_chunk(
                    handler.wfile,
                    f"Warning: The recommended RHEL OS versions are {RECOMMENDED_RHEL_VERSION[0]} and {RECOMMENDED_RHEL_VERSION[1]}"
                )
        return os_name, os_version
    except Exception as e:
        write_chunk(
            handler.wfile,
            (
                f"End: Could not detect OS. Encountered Error: {str(e)}. "
                f"Please switch to one of the supported OS: {RECOMMENDED_HOST_OS}"
            ),
        )
        return "", ""


def execute_command(command, env=None, shell=False, input_data=None):
    """
    Execute a command and yield its output.

    Args:
        command (list): The command to execute with its arguments.
        env (dict): The environment variables to set.
        shell (bool): Whether to use the shell or not.
        input_data (str): The input data to provide to the command.

    Yields:
        dict: The messages from the command execution. The keys are:
            type (str): The type of message. The possible values are:
                stdout: The message is from the command's standard output.
                stderr: The message is from the command's standard error.
                returncode: The message is the return code of the command.
            message (str): The message content.
            attempt (int): The number of the attempt. Only set if type is retry.

    Raises:
        Exception: If the command execution failed.
    """
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if input_data else None,
        text=True,
        bufsize=1,
        env=env,
        universal_newlines=True,  # Ensures proper line handling
        shell=shell,
    )

    try:
        if input_data:
            process.stdin.write(input_data)
            process.stdin.close()

        for output in iter(process.stdout.readline, ""):  # Read stdout line by line
            yield {"type": "stdout", "message": output}

        for error in iter(process.stderr.readline, ""):  # Read stderr line by line
            yield {"type": "stderr", "message": error}
    finally:
        process.wait()  # Ensure the process completes
        yield {"type": "returncode", "code": process.returncode}


def execute_command_with_logging(
    command, handler, shell=False, input_data=None, should_end_stream=False, message=""
):
    """
    Execute a command and stream the output to the client.

    Args:
        command (List[str]): The command to execute.
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        shell (bool, optional): Whether to use the shell to execute the command. Defaults to False.
        input_data (str, optional): Data to send to the command as input. Defaults to None.
        should_end_stream (bool, optional): Whether to end the stream after executing the command. Defaults to False.
        message (str, optional): A message to write to the client before executing the command. Defaults to "".

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        Exception: If an exception occurs while executing the command.
    """
    try:
        for message_stream in execute_command(
            command, input_data=input_data, shell=shell
        ):
            message_str = message_stream.get("message", "\n")
            type_str = message_stream.get("type", "")
            if type_str == "stderr":
                write_chunk(handler.wfile, f"Error: {message_str}")
            elif type_str == "returncode" and message_stream.get("code", 0) != 0:
                write_chunk(
                    handler.wfile,
                    f"End: Command failed with return code: {str(message_stream.get('code', 0))}. While {message}\n",
                )
                return {
                    "detail": f"Command failed with return code: {str(message_stream.get('code', 0))} While {message}"
                }, 500
            else:
                write_chunk(handler.wfile, f"Info: {message_str}")
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while {message}. Error: {str(e)} Traceback: {traceback.format_exc()}\n",
        )
        return {"detail": f"Error encountered while {message}. Error: {str(e)}"}, 500
    finally:
        end_stream(handler=handler, should_end_stream=should_end_stream)
    return {"detail": "Command executed successfully."}, 200


def install_gluster(
    handler,
    shared_directory_path,
    glusterfs_base_port,
    glusterfs_max_port,
    should_end_stream=True,
):
    """Install glusterfs on a remote server.

    Args:
        handler: The web server request handler.
        shared_directory_path (str): The path to the shared directory.
        glusterfs_base_port (int): The base port for glusterfs.
        glusterfs_max_port (int): The maximum port for glusterfs.

        should_end_stream (bool, optional): Should end the streaming response. Defaults to True.

    Returns:
        dict: json response for internal handling.
    """
    shared_directory_path = shared_directory_path.strip().rstrip("/")

    if (not isinstance(shared_directory_path, str)) or (
        isinstance(shared_directory_path, str) and len(shared_directory_path) == 0
    ):
        write_chunk(handler.wfile, "Please provide valid shared directory path.")
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Please provide valid shared directory path."}, 400
    if not is_strict_pathlike(shared_directory_path):
        write_chunk(handler.wfile, "Provided path is not valid.")
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Provided path is not valid."}, 400
    should_install_gluster = True
    # Check if GlusterFS is already installed
    try:
        gluster_check_cmd = f"{SUDO_PREFIX} gluster --version".strip()
        glusterd_check_cmd = f"{SUDO_PREFIX} glusterd --version".strip()
        glusterfs_check_cmd = f"{SUDO_PREFIX} glusterfs --version".strip()

        gluster_return_code = -1
        for result in execute_command(gluster_check_cmd, shell=True):
            if result.get("type") == "returncode":
                gluster_return_code = result.get("code", -1)

        glusterd_return_code = -1
        for result in execute_command(glusterd_check_cmd, shell=True):
            if result.get("type") == "returncode":
                glusterd_return_code = result.get("code", -1)

        glusterfs_return_code = -1
        for result in execute_command(glusterfs_check_cmd, shell=True):
            if result.get("type") == "returncode":
                glusterfs_return_code = result.get("code", -1)

        if gluster_return_code == 0 and glusterd_return_code == 0 and glusterfs_return_code == 0:
            write_chunk(
                handler.wfile,
                "Info: GlusterFS is already installed, skipping installation.\n",
            )
            should_install_gluster = False
    except Exception:
        # If commands fail, GlusterFS is not installed, so proceed with installation.
        pass

    if should_install_gluster:
        write_chunk(handler.wfile, "Info: Installing GlusterFS.\n")
        os_name, os_version = get_os_name_and_major_version(handler=handler)
        if not os_name or not os_version:
            write_chunk(
                handler.wfile,
                "End: Unable to check OS version."
            )
            end_stream(handler=handler, should_end_stream=should_end_stream)
            return {"detail": "OS version check failed."}, 400
        if os_name.lower() == "ubuntu":
            response = install_on_ubuntu(handler=handler)
            if response[1] != 200:
                end_stream(handler=handler, should_end_stream=should_end_stream)
                return response
        elif os_name.lower() == "rhel":
            response = install_on_rhel(handler=handler, version=os_version)
            if response[1] != 200:
                end_stream(handler=handler, should_end_stream=should_end_stream)
                return response
        write_chunk(handler.wfile, "Info: GlusterFS installation completed.\n")

    write_chunk(
        handler.wfile,
        "Info: Updating GlusterFS ports, "
        + f"Setting base port with {glusterfs_base_port} and max port with {glusterfs_max_port}\n",
    )
    success = update_glusterd_ports(
        file_path="/etc/glusterfs/glusterd.vol",
        listen_port=24007,
        base_port=glusterfs_base_port,
        max_port=glusterfs_max_port,
    )
    if not success:
        write_chunk(
            handler.wfile,
            "End: Error encountered while updating the GlusterFS volume file.\n",
        )
        return {
            "detail": "Error encountered while updating the GlusterFS volume file."
        }, 500
    write_chunk(handler.wfile, "Info: Updated GlusterFS ports.\n")

    write_chunk(handler.wfile, "Info: Starting GlusterFS.\n")
    gluster_start_command = f"{SUDO_PREFIX} systemctl enable glusterd && {SUDO_PREFIX} systemctl restart glusterd"
    for command in gluster_start_command.split("&&"):
        command = command.strip().split(" ")
        response = execute_command_with_logging(
            command, handler, message="starting glusterd service"
        )
        if response[1] != 200:
            end_stream(handler=handler, should_end_stream=should_end_stream)
            return response
    write_chunk(handler.wfile, "Info: glusterd service started.\n")

    write_chunk(handler.wfile, "Info: Creating directories for GlusterFS volume\n")
    command_for_mkdirs = (
        f"{SUDO_PREFIX} mkdir -p {shared_directory_path}/gluster/bricks/1/brick "
        f"&& {SUDO_PREFIX} mkdir -p {shared_directory_path}/data/"
    )

    for command in command_for_mkdirs.split("&&"):
        command = command.strip().split(" ")
        response = execute_command_with_logging(
            command, handler, message="creating GlusterFS directories"
        )
        if response[1] != 200:
            end_stream(handler=handler, should_end_stream=should_end_stream)
            return response
    write_chunk(handler.wfile, "Info: GlusterFS directories created.\n")
    end_stream(handler=handler, should_end_stream=should_end_stream)
    return {"detail": "GlusterFS installation completed."}, 200


def update_glusterd_ports(file_path, listen_port, base_port, max_port):
    """
    Update glusterd.vol file with new port values.

    Args:
        file_path (str): Path to the glusterd.vol file.
        listen_port (int): Port number for glusterd to listen on.
        base_port (int): The base port number for glusterd to use.
        max_port (int): The maximum port number glusterd can use.

    Raises:
        FileNotFoundError: If the glusterd.vol file is not found.
    """
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error(
            f"Glusterd.vol file not found: {file_path}, Creating it.",
            extra={"node": NODE_IP},
        )
        with open(file_path, "a") as f:
            pass
        lines = []

    # Detect if volume management block exists
    mgmt_start = any("volume management" in line for line in lines)
    in_mgmt_block = False
    updated_lines = []
    inserted = {"listen": False, "base": False, "max": False}

    if not mgmt_start:
        # If file is empty or no management block, insert a full block
        updated_lines = [
            "volume management\n",
            "    type mgmt/glusterd\n",
            "    option working-directory /var/lib/glusterd\n",
            f"    option transport.socket.listen-port {listen_port}\n",
            f"    option base-port {base_port}\n",
            f"    option max-port  {max_port}\n",
            "    option ping-timeout 0\n",
            "end-volume\n",
        ]
    else:
        for line in lines:
            stripped = line.strip()

            if stripped.startswith("volume management"):
                in_mgmt_block = True

            if in_mgmt_block and "option transport.socket.listen-port" in stripped:
                line = f"    option transport.socket.listen-port {listen_port}\n"
                inserted["listen"] = True
            elif in_mgmt_block and "option base-port" in stripped:
                line = f"    option base-port {base_port}\n"
                inserted["base"] = True
            elif in_mgmt_block and "option max-port" in stripped:
                line = f"    option max-port  {max_port}\n"
                inserted["max"] = True

            updated_lines.append(line)

            if in_mgmt_block and stripped == "end-volume":
                if not inserted["listen"]:
                    updated_lines.insert(
                        -1, f"    option transport.socket.listen-port {listen_port}\n"
                    )
                if not inserted["base"]:
                    updated_lines.insert(-1, f"    option base-port {base_port}\n")
                if not inserted["max"]:
                    updated_lines.insert(-1, f"    option max-port  {max_port}\n")
                in_mgmt_block = False

    with open(file_path, "w") as f:
        f.writelines(updated_lines)

    logger.info(f"Info: Updated {file_path}.", extra={"node": NODE_IP})

    return True


def install_on_ubuntu(handler):
    """
    Install glusterfs on Ubuntu/Debian.

    Args:
        handler: The web server request handler.

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.
    """
    # Install GlusterFS
    try:
        write_chunk(
            handler.wfile,
            "Info: Fetching GlusterFS GPG key from keyserver.ubuntu.com\n",
        )
        read_cloud_exchange_config_file()
        set_proxy()
        pgp_url = "http://keyserver.ubuntu.com/pks/lookup?op=get&search=0xF7C73FCC930AC9F83B387A5613E01B7B3FE869A9"
        req = urllib.request.Request(pgp_url)
        proxy = None
        if AVAILABLE_INPUTS.get("CORE_HTTPS_PROXY", "") != "":
            proxy = AVAILABLE_INPUTS.get("CORE_HTTPS_PROXY")

        proxies = {}

        if proxy is not None:
            proxies["http"] = proxy
            proxies["https"] = proxy

        proxy_support = urllib.request.ProxyHandler(proxies=proxies)
        opener = urllib.request.build_opener(proxy_support)
        urllib.request.install_opener(opener)

        response = urllib.request.urlopen(req, timeout=60)

        if response.status != 200:
            write_chunk(
                handler.wfile,
                f"End: Error encountered while fetching GPG key from Ubuntu keyserver. HTTP status: {response.status}\n",
            )
            end_stream(handler=handler)
            return {
                "detail": f"Failed to fetch GPG key. HTTP status: {response.status}"
            }, 500

        pgp_key = response.read()
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while fetching GPG key from Ubuntu keyserver. Error: {e}\n",
        )
        end_stream(handler=handler)
        return {"detail": f"Error fetching GPG key: {str(e)}"}, 500

    if os.path.exists("/etc/apt/trusted.gpg.d/gluster.gpg"):
        write_chunk(
            handler.wfile,
            "Info: GPG key already exists at /etc/apt/trusted.gpg.d/gluster.gpg removing it.\n",
        )
        os.unlink("/etc/apt/trusted.gpg.d/gluster.gpg")

    decoded_key = pgp_key.decode("utf-8").replace('"', '\\"')
    gpg_cmd = f'echo "{decoded_key}" | {SUDO_PREFIX} gpg --dearmor -o /etc/apt/trusted.gpg.d/gluster.gpg'

    response = execute_command_with_logging(
        gpg_cmd,
        handler,
        shell=True,
        message="importing GPG key",
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response
    write_chunk(handler.wfile, "Info: GPG key imported successfully.\n")

    codename = None
    for result in execute_command(f"{SUDO_PREFIX} lsb_release -sc", shell=True):
        if result["type"] == "stdout":
            codename = result["message"].strip()
        elif result["type"] == "stderr":
            logger.error(
                f"Error encountered while fetching release information. {result['message']}",
                extra={"node": NODE_IP},
            )
        elif result["type"] == "returncode" and result["code"] != 0:
            logger.error(
                f"Error encountered while fetching release information. Process exited with {result['code']}.",
                extra={"node": NODE_IP},
            )
    if codename is None:
        write_chunk(
            handler.wfile,
            "End: Error encountered while fetching release information for machine.\n",
        )
        end_stream(handler=handler)
        return {
            "details": "Error encountered while fetching release information for machine."
        }, 500

    # Add the GlusterFS repository
    repo_line = f"deb [signed-by=/etc/apt/trusted.gpg.d/gluster.gpg] http://ppa.launchpad.net/gluster/glusterfs-11/ubuntu {codename} main"
    cat_cmd = f"{SUDO_PREFIX} bash -c 'echo \"{repo_line}\" | tee /etc/apt/sources.list.d/glusterfs-ppa.list'"
    response = execute_command_with_logging(
        cat_cmd, handler, shell=True, message="adding GlusterFS repository"
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response

    write_chunk(handler.wfile, "Info: GlusterFS repository added.\n")
    write_chunk(handler.wfile, "Info: Installing GlusterFS.\n")
    command_for_installation = (
        f"{SUDO_PREFIX} apt update && DEBIAN_FRONTEND=noninteractive "
        f"{SUDO_PREFIX} apt install xfsprogs attr glusterfs-server glusterfs-common glusterfs-client glusterfs-cli -y"
    )

    for command in command_for_installation.split("&&"):
        response = execute_command_with_logging(
            command, handler, shell=True, message="installing GlusterFS"
        )
        if response[1] != 200:
            end_stream(handler=handler)
            return response
    write_chunk(handler.wfile, "Info: GlusterFS installed on Ubuntu.\n")
    return {"detail": "GlusterFS installed."}, 200


def install_on_rhel(handler, version):
    """
    Install glusterfs on RHEL.

    Args:
        handler: The web server request handler.
        version (str): The major version of RHEL (e.g. 9).

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.

    Raises:
        HTTPException: If there is an error installing GlusterFS.
    """
    command = rf"""
{SUDO_PREFIX} tee /etc/yum.repos.d/glusterfs-11.repo > /dev/null <<EOF
[glusterfs-11]
name=GlusterFS 11 - Storage SIG
baseurl=https://buildlogs.centos.org/centos/{version}-stream/storage/x86_64/gluster-11/
gpgcheck=0
enabled=1
EOF
"""
    # Do not prettify the command.
    response = execute_command_with_logging(
        command, handler, shell=True, message="adding GlusterFS repository"
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response

    commands = (
        f"{SUDO_PREFIX} yum install attr -y && {SUDO_PREFIX} yum install glusterfs -y "
        f"&& {SUDO_PREFIX} yum install glusterfs-fuse -y && {SUDO_PREFIX} yum install glusterfs-cli -y "
        f"&& {SUDO_PREFIX} yum install rpcbind -y && {SUDO_PREFIX} yum install glusterfs-server -y"
    )

    for command in commands.split("&&"):
        response = execute_command_with_logging(
            command, handler, shell=True, message="installing GlusterFS"
        )
        if response[1] != 200:
            end_stream(handler=handler)
            return response
    write_chunk(handler.wfile, "Info: GlusterFS installed on RHEL.\n")
    return {"detail": "GlusterFS installed."}, 200


def write_chunk(wfile, data: str, node_ip=None, skip_log=False):
    """
    Write a chunk of data to the client over SSL socket.

    Args:
        wfile (wsgiref.handlers.HTTPResponse): The file like object to write to.
        data (str): The data to write.
        node_ip (str, optional): The IP address of the node. Defaults to None.
        skip_log (bool, optional): Whether to skip logging the data. Defaults to False.

    """
    encoded = data.encode("utf-8")
    if not skip_log:
        if node_ip is None or node_ip == "":
            node_ip = NODE_IP
        logger.info(f"{encoded}", extra={"node": node_ip})
    try:
        chunk_len = f"{len(encoded):X}\r\n".encode("utf-8")
        complete_chunk = chunk_len + encoded + b"\r\n"
        wfile.write(complete_chunk)
        wfile.flush()
    except (BrokenPipeError, ConnectionResetError):
        logger.warning(
            "Connection reset by peer, streaming skipped.", extra={"node": NODE_IP}
        )
    except ssl.SSLEOFError as e:
        logger.warning(
            f"SSL connection closed while writing {complete_chunk} to {node_ip}: {e}",
            extra={"node": node_ip},
        )
    except ssl.SSLError as e:
        logger.warning(
            f"SSL BAD_LENGTH error while writing {complete_chunk} for {node_ip}. Error: {e}, continuing with other chunks",
            extra={"node": node_ip},
        )
    return


def get_node_ip():
    """
    Get the IP address of the current node.

    Returns:
        Tuple[Dict[str, str], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with the IP address of the current node.
    """
    global NODE_IP
    try:
        result = subprocess.check_output(
            f"{SUDO_PREFIX}".strip()
            + "ip route get 8.8.8.8 | awk '/src/ { for (i=1; i<=NF; i++) if ($i==\"src\") print $(i+1) }'",
            shell=True,
            text=True,
        )  # this does not make call, just identifies the route.
        NODE_IP = result.strip()
        return {"detail": NODE_IP}, 200
    except Exception as e:
        logger.error(
            f"Error encountered while fetching host machine's ip. Error : {str(e)}",
            extra={"node": NODE_IP},
        )
        return {"detail": "Error encountered while fetching host machine's ip."}, 500


def unmount_volume(handler, shared_directory_path=None, should_end_stream=True, should_remove_brick_data=False):
    """
    Unmount glusterfs volume.

    Args:
        handler (Handler): The handler object.
        shared_directory_path (str): The path to the shared directory.
        should_end_stream(bool): Should stream be terminated.
        should_remove_brick_data(bool): Should clear the glusterfs volume brick directory.

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.

    Raises:
        HTTPException: If there is an error unmounting the volume.
    """
    shared_directory_path = shared_directory_path.strip().rstrip("/")

    if (not isinstance(shared_directory_path, str)) or (
        isinstance(shared_directory_path, str) and len(shared_directory_path) == 0
    ):
        write_chunk(handler.wfile, "Please provide valid shared directory path.")
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Please provide valid shared directory path."}, 400
    if not is_strict_pathlike(shared_directory_path):
        write_chunk(handler.wfile, "Provided path is not valid.")
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Provided path is not valid."}, 400
    # Unmount
    write_chunk(handler.wfile, "Info: un-mounting existing volume.\n")
    command_for_umount = f"{SUDO_PREFIX} umount {shared_directory_path}/data"
    command = command_for_umount.strip()
    try:
        is_not_mounted = False
        for message in execute_command(command, shell=True):
            if is_not_mounted:
                continue
            message_str = message.get("message", "\n")
            type_str = message.get("type", "")
            if type_str == "stderr":
                if "not mounted." in message_str:
                    write_chunk(handler.wfile, "Info: Volume is already unmounted.\n")
                    is_not_mounted = True
                write_chunk(handler.wfile, f"Error: {message_str}")
            elif type_str == "returncode" and message.get("code", 0) != 0:
                write_chunk(
                    handler.wfile,
                    (
                        "End: Could not unmount CloudExchange GlusterFS volume. "
                        f"Command failed with return code: {str(message.get('code', 0))}.\n"
                    ),
                )
                return {
                    "detail": (
                        "Could not unmount CloudExchange GlusterFS volume. "
                        f"Command failed with return code: {str(message.get('code', 0))}"
                    )
                }, 500
            else:
                write_chunk(handler.wfile, f"Info: {message_str}")
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while un-mounting GlusterFS volume. Error: {str(e)}\n",
        )
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Error encountered while un-mounting GlusterFS volume."}, 500

    if should_remove_brick_data:
        # remove GlusterFS brick data
        write_chunk(handler.wfile, f"Info: Removing GlusterFS brick data from {shared_directory_path}/gluster .\n")
        command = f"{SUDO_PREFIX} rm -rf {shared_directory_path}/gluster".strip()
        response = execute_command_with_logging(
            command, handler, shell=True, message="removing GlusterFS brick data"
        )
        if response[1] != 200:
            end_stream(handler=handler)
            return {"detail": "Error encountered while removing GlusterFS brick data."}, 500
        end_stream(handler=handler, should_end_stream=should_end_stream)
    return {"detail": "Volume unmounted"}, 200


def has_data(path):
    """Check if the directory is empty or not.

    Args:
        path (str): Path like string.

    Returns:
        bool: True if the directory has data, otherwise False.
    """
    return os.path.isdir(path) and any(os.scandir(path))


def move_data(src, dest):
    """Move data from src to dest.

    Args:
        src (str): Source directory.
        dest (str): Destination directory.
    """
    os.makedirs(dest, exist_ok=True)
    for entry in os.listdir(src):
        shutil.move(os.path.join(src, entry), os.path.join(dest, entry))


def ensure_volume_mounted(
    handler, shared_directory_path="", current_node_ip="", should_end_stream=True
):
    """
    Ensure that the glusterfs volume is mounted.

    Args:
        handler: The web server request handler.
        shared_directory_path (str): The path to the shared directory.
        current_node_ip (str): The IP address of the current node.
        should_end_stream(bool): Should stream be terminated.

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.

    Raises:
        HTTPException: If there is an error mounting the volume.
    """
    if current_node_ip == "" or shared_directory_path == "":
        write_chunk(
            handler.wfile,
            "End: Please provide a valid shared directory path and current node ip.\n",
        )
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {
            "detail": "Please provide a valid shared directory path and current node ip."
        }, 400

    shared_directory_path = shared_directory_path.strip().rstrip("/")
    if (not isinstance(shared_directory_path, str)) or (
        isinstance(shared_directory_path, str) and len(shared_directory_path) == 0
    ):
        write_chunk(handler.wfile, "Please provide valid shared directory path.")
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Please provide valid shared directory path."}, 400
    elif not is_strict_pathlike(shared_directory_path):
        write_chunk(handler.wfile, "Provided path is not valid.")
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Provided path is not valid."}, 400
    elif (not isinstance(current_node_ip, str)) or (
        not validate_network_address(current_node_ip)
    ):
        write_chunk(handler.wfile, "Invalid node ip provided")
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Invalid node ip provided"}, 400

    response = unmount_volume(
        handler=handler,
        shared_directory_path=shared_directory_path,
        should_end_stream=False,
    )
    if response[1] != 200:
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return response

    src_directory = shared_directory_path + "/data"
    if len(src_directory.rsplit("/", 1)) > 1:
        backup_dir = src_directory.rsplit("/", 1)[0] + "/backup"
    else:
        backup_dir = "/opt/shared/backup"
    if has_data(src_directory):
        write_chunk(
            handler.wfile,
            f"Info: Existing data found in {src_directory}. Moving to {backup_dir}. It will be restored after mount.\n",
        )
        move_data(src_directory, backup_dir)
        write_chunk(handler.wfile, f"Info: Moved existing data to {backup_dir}.\n")
    write_chunk(handler.wfile, "Info: Mounting GlusterFS volume.\n")
    command_for_mount = (
        f"{SUDO_PREFIX} mount -t glusterfs {current_node_ip}:/CloudExchange "
        f"{src_directory}"
    )
    command = command_for_mount.strip().split(" ")
    response = execute_command_with_logging(
        command, handler, message="mounting GlusterFS volume"
    )
    if has_data(backup_dir):
        write_chunk(
            handler.wfile,
            f"Info: Restoring data to {src_directory} directory...\n",
        )
        move_data(backup_dir, src_directory)
        write_chunk(
            handler.wfile,
            f"Info: Restored data to {src_directory} directory ...\n",
        )
    if response[1] != 200:
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return {"detail": "Error encountered while mounting GlusterFS volume."}, 500

    write_chunk(handler.wfile, "Info: Successfully mounted GlusterFS volume.\n")
    end_stream(handler=handler, should_end_stream=should_end_stream)
    return {"detail": "Successfully mounted GlusterFS volume."}, 200


def ce_as_vm_check():
    """
    Check if the current CE deployment is running as a VM.

    We use an environment variable to check if the deployment is running
    as a VM. This variable is set when CE is deployed as a VM.

    Returns:
        bool: True if CE is running as a VM, False otherwise.
    """
    return os.path.exists("/.cloud_exchange_vm.marker") and os.path.exists(
        "./ce_as_vm_tags.py"
    )


def change_maintenance_password(raw_text: str, forward=True):
    """
    Change the maintenance password with the given raw text.

    If the raw text is the same as the current password, this function does
    nothing. Otherwise, it changes the password and updates the
    maintenance password file.

    Args:
        raw_text: The raw text of the new password.
        forward: Whether to forward the request to the HA server. Defaults to
            True.
    """
    try:
        CE_SETUP_ID = None
        CE_HEX_CODE = None
        CE_IV = None
        if not AVAILABLE_INPUTS.get("CE_SETUP_ID", ""):
            CE_SETUP_ID = generate_ce_setup_id()
            AVAILABLE_INPUTS["CE_SETUP_ID"] = f'"{CE_SETUP_ID}"'
            AVAILABLE_INPUTS["CE_HEX_CODE"] = os.urandom(8).hex().upper()
            AVAILABLE_INPUTS["CE_IV"] = os.urandom(16).hex()
        CE_HEX_CODE = AVAILABLE_INPUTS["CE_HEX_CODE"]
        CE_IV = AVAILABLE_INPUTS["CE_IV"]
        CE_SETUP_ID = AVAILABLE_INPUTS["CE_SETUP_ID"].strip('"')
        command = f"""echo -n '{CE_SETUP_ID}' | openssl dgst -sha256 -hex | awk '{{print $2}}'"""
        process = subprocess.Popen(
            command,
            shell=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        out, err = process.communicate()
        if process.returncode == 0:
            processed_stream = out.decode().strip()
            # generate mpass
            if forward:
                second_command = (
                    f"echo '{raw_text}' | openssl enc -aes-256-cbc -a -S {CE_HEX_CODE} "
                    f"-K '{processed_stream}' -iv {CE_IV} -pbkdf2 -iter 10000"
                )
                second_process = subprocess.Popen(
                    second_command,
                    shell=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                )
                sec_out, sec_err = second_process.communicate()
                if second_process.returncode == 0:
                    return sec_out.decode().strip()
                else:
                    raise Exception(f"{sec_err.decode('utf-8')}\n")
            else:
                third_command = (
                    f"echo '{raw_text}' | openssl enc -aes-256-cbc -d -a -S {CE_HEX_CODE} "
                    f"-K '{processed_stream}' -iv {CE_IV} -pbkdf2 -iter 10000"
                )
                third_process = subprocess.Popen(
                    third_command,
                    shell=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                )
                third_out, third_err = third_process.communicate()
                if third_process.returncode == 0:
                    return third_out.decode().strip()
                else:
                    raise Exception(f"{third_err.decode('utf-8')}\n")
        else:
            raise Exception(f"{err.decode('utf-8')}\n")
    except Exception as e:
        raise Exception(
            f"Error occurred while processing environment variables. Error: {e}"
        )


def set_directory_permission(directory, command):
    """
    Set directory permissions.

    Args:
        directory: The path to the directory.
        command: The command to use for setting permissions.
            For example, 'chmod 700' or 'chown netskope:netskope'.

    Raises:
        Exception: If there is an error running the command.
    """
    p = None
    try:
        p = subprocess.Popen(
            command.split(),
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        out, err = p.communicate()
        if len(err) <= 0:
            return
        else:
            raise Exception(err.decode("utf-8"))
    except Exception as e:
        if p:
            p.kill()
        raise Exception(
            f"Error occurred while setting file permissions for {directory}. Error: {e}"
        )


def create_secret_file(passwords, location):
    """
    Create a secret file at the specified location with the given passwords.

    Args:
        passwords (dict): A dictionary of passwords.
        location (str): The location of the secret file.

    Raises:
        Exception: If there is an error creating the secret file.

    Returns:
        None
    """
    mpass_without_quote = passwords["MAINTENANCE_PASSWORD"][1:-1]
    mpass = change_maintenance_password(mpass_without_quote)
    passwords["MAINTENANCE_PASSWORD"] = change_maintenance_password(
        passwords["MAINTENANCE_PASSWORD"]
    )
    passwords["MAINTENANCE_PASSWORD_ESCAPED"] = change_maintenance_password(
        passwords["MAINTENANCE_PASSWORD_ESCAPED"]
    )
    passwords["RABBITMQ_DEFAULT_PASS"] = mpass
    passwords["MONGO_INITDB_ROOT_PASSWORD"] = mpass
    passwords["MONGODB_PASSWORD"] = mpass

    with open(location, "w") as f:
        for key, value in passwords.items():
            f.write(f"{key}={value}\n")
    command = f"{SUDO_PREFIX} chmod 400 {location}"
    set_directory_permission(location, command)


def get_secret_location(inputs):
    """
    Get the location of the .env file.

    The location of the .env file depends on the deployment type.
    For a normal deployment, the .env file is in the current directory.
    If CE is deployed as a VM, the .env file is under /etc.
    If CE is running in HA mode, the .env file is under
    HA_NFS_DATA_DIRECTORY/config.

    Args:
        inputs (dict): The inputs dictionary.

    Returns:
        str: The location of the .env file. If the .env file does not exist,
        or if CE is not running in HA mode, the location is None.
    """
    secret_location = SECRET_FILE_NAME
    if ce_as_vm_check():
        secret_location = f"/etc/{SECRET_FILE_NAME}"
    if "HA_IP_LIST" in inputs.keys():
        if not inputs.get("HA_NFS_DATA_DIRECTORY", None):
            secret_location = None
        else:
            secret_dir_path = os.path.join(inputs["HA_NFS_DATA_DIRECTORY"], "config")
            ensure_dir_exists(secret_dir_path)
            secret_location = os.path.join(secret_dir_path, SECRET_FILE_NAME)
    return secret_location


def generate_ce_setup_id():
    """
    Generate a random string as the CE setup ID.

    Returns:
        str: the CE setup ID
    """
    return b64encode(token_bytes(32)).decode("utf-8")


def ensure_dir_exists(dir_path):
    """
    Ensure that the given directory exists.

    If the directory does not exist, it will be created.
    The parent directory must exist.

    Args:
        dir_path (str): The path to the directory to create.
    """
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        os.chmod(dir_path, 0o755)


def stop_delete_gluster_volume(handler):
    """
    Stop and delete an existing GlusterFS volume.

    Args:
        handler: The web server request handler.

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.
    """
    write_chunk(handler.wfile, "Info: Stopping existing GlusterFS volume\n")
    command_for_stop = f"{SUDO_PREFIX} gluster volume stop CloudExchange".strip().split(
        " "
    )
    response = execute_command_with_logging(
        command_for_stop,
        handler,
        input_data="y\n",
        message="stopping existing GlusterFS volume",
    )
    if response[1] != 200:
        return response
    write_chunk(handler.wfile, "Info: Existing GlusterFS volume stopped.\n")

    write_chunk(handler.wfile, "Info: Removing existing GlusterFS volume.\n")
    command_for_remove = (
        f"{SUDO_PREFIX} gluster volume delete CloudExchange".strip().split(" ")
    )
    response = execute_command_with_logging(
        command_for_remove,
        handler,
        input_data="y\n",
        message="removing existing GlusterFS volume",
    )
    if response[1] != 200:
        return response
    write_chunk(handler.wfile, "Info: Existing GlusterFS volume removed.\n")

    return {"detail": "Existing GlusterFS volume removed."}, 200


def verify_start_create_volume(
    handler, current_node_ip, shared_directory_path="/opt/shared"
):
    """
    Verify and start/create a new GlusterFS volume.

    Args:
        handler: The web server request handler.
        current_node_ip: The IP address of the current node.
        shared_directory_path (str): The path to the shared directory. Defaults to "/opt/shared".

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.
    """
    write_chunk(handler.wfile, "Info: Checking for existing GlusterFS volume.\n")
    command_for_check = f"{SUDO_PREFIX} gluster volume list"
    command = command_for_check.strip().split(" ")
    try:
        volume_exists = False
        for message in execute_command(command):
            if volume_exists:
                continue
            message_str = message.get("message", "\n")
            type_str = message.get("type", "")
            if type_str == "stderr":
                write_chunk(handler.wfile, f"Error: {message_str}")
            elif type_str == "returncode" and message.get("code", 0) != 0:
                write_chunk(
                    handler.wfile,
                    (
                        "End: Could not fetch existing GlusterFS volume. "
                        f"Command failed with return code: {str(message.get('code', 0))}.\n"
                    ),
                )
                return {
                    "detail": (
                        "Could not fetch existing GlusterFS volume. "
                        f"Command failed with return code: {str(message.get('code', 0))}"
                    )
                }, 500
            else:
                write_chunk(handler.wfile, f"Info: {message_str}")
                if "CloudExchange" in message_str:
                    write_chunk(
                        handler.wfile,
                        "Info: CloudExchange GlusterFS volume already exists.\n",
                    )
                    volume_exists = True
                    continue
                else:
                    volume_exists = False
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while checking for existing GlusterFS volume. Error: {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while checking for existing GlusterFS volume. Error: {str(e)}"
        }, 500

    if volume_exists:
        response = stop_delete_gluster_volume(handler=handler)
        if response[1] != 200:
            end_stream(handler=handler)
            return response
        response = unmount_volume(
            handler=handler,
            shared_directory_path=shared_directory_path,
            should_end_stream=False,
        )
        if response[1] != 200:
            end_stream(handler=handler)
            return response

    # for primary node only, if not exists initialize volume.
    write_chunk(handler.wfile, "Info: Creating GlusterFS volume.\n")
    command_for_single_node_gluster = (
        f"{SUDO_PREFIX} gluster volume create CloudExchange "
        f"{current_node_ip}:{shared_directory_path}/gluster/bricks/1/brick force"
    )
    for command in command_for_single_node_gluster.split("&&"):
        command = command.strip().split(" ")
        response = execute_command_with_logging(
            command, handler, message="creating GlusterFS volume"
        )
        if response[1] != 200:
            end_stream(handler=handler)
            return response
    write_chunk(handler.wfile, "Info: GlusterFS volume created.\n")

    # start GlusterFS
    write_chunk(handler.wfile, "Info: Starting GlusterFS volume.\n")
    start_gluster = f"{SUDO_PREFIX} gluster volume start CloudExchange"
    command = start_gluster.strip().split(" ")
    response = execute_command_with_logging(
        command, handler, message="starting GlusterFS volume"
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response
    write_chunk(handler.wfile, "Info: Successfully started GlusterFS volume.\n")

    return {"detail": "GlusterFS volume created."}, 200


def end_stream(handler, should_end_stream=True):
    """
    End the stream of a wsgi response.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        should_end_stream (bool, optional): Whether to end the stream. Defaults to True.
    """
    if should_end_stream:
        try:
            handler.wfile.write(b"0\r\n\r\n")
            handler.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            logger.warning(
                "Connection reset by peer, streaming skipped.", extra={"node": NODE_IP}
            )
        except ssl.SSLEOFError as e:
            logger.warning(
                f"SSL connection closed while: {e}.", extra={"node": NODE_IP}
            )
        except ssl.SSLError as e:
            logger.warning(
                f"SSL BAD_LENGTH error. Error: {e}.", extra={"node": NODE_IP}
            )
        handler.close_connection = True
        return


def set_sudo_prefix():
    """Get sudo prefix."""
    global SUDO_PREFIX
    if hasattr(os, "geteuid"):
        euid = os.geteuid()
        if euid == 0:
            SUDO_PREFIX = ""
        else:
            SUDO_PREFIX = "sudo"
    else:
        SUDO_PREFIX = "sudo"


def is_strict_pathlike(path_str, allowed_abs_prefix="/opt"):
    """
    Strict validation of path-like strings with absolute path restriction to /opt.

    Args:
        path_str: Path string to validate
        allowed_abs_prefix: The only allowed prefix for absolute paths (default: "/opt")

    Returns:
        bool: True if valid path that meets all criteria
    """
    if not isinstance(path_str, str) or not path_str:
        return False

    # Check for command injection patterns (expanded)
    if re.search(r"[;&|`\$\n\r\x00]", path_str):
        return False

    # Check for suspicious command patterns
    if re.search(r"\s(&&|\|\||>>|<<|>|<)\s", path_str, re.IGNORECASE):
        return False

    # Check for parent directory traversal
    if ".." in PurePath(path_str).parts:
        return False

    try:
        path = Path(path_str)
        if "\\" in str(path) and ("/" in str(path)):
            return False
        if path.is_absolute():
            path_str_normalized = str(path).replace("\\", "/")
            if not path_str_normalized.startswith(allowed_abs_prefix + "/"):
                return False

            # Additional checks for absolute paths
            if not os.path.isabs(allowed_abs_prefix):
                # print("from withing2")
                return False

            # Prevent paths like /opt/../etc/passwd
            resolved = str(path.resolve()).replace("\\", "/")
            if not resolved.startswith(allowed_abs_prefix + "/"):
                return False
        return True
    except (RuntimeError, ValueError, Exception) as e:
        logger.debug(f"Path check failed. Error {e}")
        return False


def validate_dns(dns_str: str):
    """Validate DNS names following modern practical standards.

    Args:
        dns_str: Domain name to validate
        allow_local: Permit .local and localhost

    Returns:
        bool: True if valid DNS name
    """
    if not isinstance(dns_str, str) or not dns_str or len(dns_str) > 253:
        return False

    # Allow underscores by default (modern practice)
    pattern = r"^([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"

    # Check standard format (now with underscores allowed)
    if not re.fullmatch(pattern, dns_str):
        # Check for localhost/local domains
        if not re.fullmatch(r"^(localhost|([a-zA-Z0-9-]+\.)*local)$", dns_str):
            return False

    # Label-level validation
    labels = dns_str.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def validate_ip(ip_str):
    """Validate the ip address format.

    Args:
        ip_str (str): The ip string to validate.

    Returns:
        bool: True if the ip string is valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_network_address(addr):
    """Validate if input is either a valid IP or DNS name.

    Args:
        addr (str): The address to validate.

    Returns:
        bool: True if the address is a valid IP or DNS name, False otherwise.
    """
    if validate_ip(addr):
        return True
    elif validate_dns(addr):
        return True
    else:
        return False


def update_cloudexchange_config(updated_config):
    """Update CloudExchange configuration with provided data.

    Args:
        config_data (dict): Dictionary containing configuration parameters
                        to update in the CloudExchange settings.

    Returns:
        bool: True if configuration was updated successfully, False otherwise.

    Raises:
        Exception: If there's an error during configuration update process.
    """
    try:
        if not os.path.exists(CONFIG_FILE_PATH):
            open(CONFIG_FILE_PATH, "w").close()

        with open(CONFIG_FILE_PATH, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            lines = f.readlines()
            f.seek(0)
            f.truncate()  # Clear the file before writing

            seen_keys = set()
            updated_keys = set()
            new_lines = []

            for line in lines:
                stripped = line.strip()

                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    new_lines.append(line)
                    continue

                key, value = stripped.split("=", 1)
                if key in seen_keys:
                    continue

                seen_keys.add(key)
                if key in updated_config.keys():
                    new_value = updated_config.get(key, value)
                    if key in KEYS_TO_REMOVE_IF_EMPTY and not new_value:
                        continue
                    new_lines.append(f"{key}={new_value}\n")
                    updated_keys.add(key)
                else:
                    if key in KEYS_TO_REMOVE_IF_EMPTY and not value:
                        continue
                    new_lines.append(line)

            for key in updated_config:
                if key not in seen_keys:
                    new_value = updated_config.get(key, "")
                    if key not in KEYS_TO_REMOVE_IF_EMPTY or new_value:
                        new_lines.append(f"{key}={new_value}\n")

            f.writelines(new_lines)
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        raise e from e


def print_warning(message):
    print(f"\033[1;93m[!] \033[0;37m{message}")


def print_fail(message):
    print(f"\033[1;31m[F] \033[1;37m{message}\033[0;37m")


def print_pass(message):
    print(f"\033[0;32m[P] \033[0;37m{message}")


def read_cloud_exchange_config_file():
    global CLOUD_EXCHANGE_CONFIG, CLOUD_EXCHANGE_CONFIG_KEYS
    try:
        if not os.path.exists("./cloudexchange.config"):
            print_warning("cloudexchange.config not found, using default values. \nTo override, create a cloudexchange.config file in the Cloud Exchange directory from the cloudexchange.config.example file. e.g cp cloudexchange.config.example cloudexchange.config")
            for key in CLOUD_EXCHANGE_CONFIG_KEYS:
                CLOUD_EXCHANGE_CONFIG[key] = CLOUD_EXCHANGE_CONFIG_KEYS[key]["default"]
            return
        with open("./cloudexchange.config", "r") as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # if "#" in line:
                #     line = line.split("#")[0].strip()
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key not in CLOUD_EXCHANGE_CONFIG_KEYS:
                    print_warning(f"Unknown key: {key}")
                    continue
                if (value.startswith("'") and value.endswith("'")) or (value.startswith('"') and value.endswith('"')):
                    value = value[1:-1]
                if not value:
                    value = CLOUD_EXCHANGE_CONFIG_KEYS[key]["default"]
                if CLOUD_EXCHANGE_CONFIG_KEYS[key]["type"] == bool and not isinstance(value, bool):
                    value = value.lower() == "true"
                elif CLOUD_EXCHANGE_CONFIG_KEYS[key]["type"] == int and not isinstance(value, int):
                    try:
                        value = int(value)
                    except:
                        print_warning(f"Invalid value for key: {key}, setting default value to {CLOUD_EXCHANGE_CONFIG_KEYS[key]['default']}.")
                        value = CLOUD_EXCHANGE_CONFIG_KEYS[key]["default"]
                else:
                    value = value
                CLOUD_EXCHANGE_CONFIG[key] = value
        if CLOUD_EXCHANGE_CONFIG.get("UI_PORT", 443) == CLOUD_EXCHANGE_CONFIG.get("CE_MANAGEMENT_PORT", 8000):
            print_fail("UI_PORT and CE_MANAGEMENT_PORT cannot be the same. Please update the cloudexchange.config file.")
            sys.exit(1)
    except Exception as e:
        print_warning(f"Error reading cloudexchange.config file: {e}")
        return


def parse_proxy(url):
    if url is None or len(url) == 0:
        return None

    url = urllib.parse.urlparse(url)
    if url.scheme is None:
        return f"{url.hostname}"
    if url.port is None:
        return f"{url.scheme}://{url.hostname}"
    return f"{url.scheme}://{url.hostname}:{url.port}"


def validate_proxy(proxy, cur_proxy=None):
    if proxy == "" and cur_proxy is not None and len(cur_proxy) >= 0:
        return True
    regex = r"^(?:(.*))://(?:(.*))$"
    result = re.search(regex, proxy)
    if result is None:
        print("Invalid Proxy Provided...")
        return False
    parts = result.groups()
    if len(parts) < 2:
        print("Invalid Proxy Provided...")
        return False
    if parts[0] not in ["http", "https"]:
        print("Invalid Protocol Provided... Valid Protocols are http/https...")
        return False
    if parts[1] == " ":
        print("Invalid Hostname Provided... It should be valid IP/FQDN...")
        return False
    return True


def prepare_proxy(url, username=None, password=None):
    if (
        username is None
        or len(username) == 0
        or password is None
        or len(password) == 0
    ):
        return url
    prefix = "https://" if url.startswith("https://") else "http://"
    url = url.replace(prefix, "")

    username = urllib.parse.quote_plus(username)
    password = urllib.parse.quote_plus(password)
    return f"{prefix}{username}:{password}@{url}"


def set_proxy():
    # CORE_HTTPS_PROXY
    cur_https_proxy = parse_proxy(
        AVAILABLE_INPUTS.get("CORE_HTTPS_PROXY", "")
    ) or ""
    https_proxy = CLOUD_EXCHANGE_CONFIG.pop("PROXY_URL", "")
    if not validate_proxy(https_proxy, cur_https_proxy):
        print_warning(
            "Invalid Proxy URL provided... Please try again with valid one. Skipping the proxy configuration."
        )
        AVAILABLE_INPUTS["CORE_HTTPS_PROXY"] = AVAILABLE_INPUTS.get("CORE_HTTPS_PROXY", "")
        AVAILABLE_INPUTS["CORE_HTTP_PROXY"] = AVAILABLE_INPUTS.get("CORE_HTTPS_PROXY", "")
        return
    if https_proxy is None or len(https_proxy) == 0:
        AVAILABLE_INPUTS["CORE_HTTPS_PROXY"] = AVAILABLE_INPUTS.get("CORE_HTTPS_PROXY", "")
        AVAILABLE_INPUTS["CORE_HTTP_PROXY"] = AVAILABLE_INPUTS.get("CORE_HTTPS_PROXY", "")
    else:
        https_proxy_username = CLOUD_EXCHANGE_CONFIG.pop("PROXY_USERNAME", "")
        https_proxy_password = CLOUD_EXCHANGE_CONFIG.pop("PROXY_PASSWORD", "")
        AVAILABLE_INPUTS["CORE_HTTPS_PROXY"] = prepare_proxy(
            https_proxy,
            username=https_proxy_username,
            password=https_proxy_password,
        )

        AVAILABLE_INPUTS["CORE_HTTP_PROXY"] = AVAILABLE_INPUTS[
            "CORE_HTTPS_PROXY"
        ]
    print(
        "\n\033[1;37mNOTE: The proxy details will be reflected on the Settings > General > Proxy page on Netskope CE UI.\n\033[0;37m"
    )
