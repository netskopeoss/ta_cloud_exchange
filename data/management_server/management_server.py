#!/usr/bin/env python3
"""Management server for the Netskope Cloud Exchange."""

import re
import base64
import fcntl
import hashlib
import hmac
import http
import http.client
import json
import os
import string
import time
import traceback
import urllib
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from json import JSONDecodeError
from urllib.parse import parse_qs, urlencode, urlparse
from datetime import datetime, timedelta
try:
    # Try to import UTC from datetime (Python 3.11+)
    from datetime import UTC
except ImportError:
    # Fall back to timezone.utc for older versions (Python 3.8-3.10)
    from datetime import timezone
    UTC = timezone.utc

import ssl

import utils
from utils import (
    SUDO_PREFIX,
    ClientExceptions,
    ServerExceptions,
    configure_logger,
    create_secret_file,
    end_stream,
    ensure_volume_mounted,
    execute_command,
    execute_command_with_logging,
    get_node_ip,
    get_secret_location,
    install_gluster,
    logger,
    set_directory_permission,
    set_sudo_prefix,
    stop_delete_gluster_volume,
    unmount_volume,
    update_cloudexchange_config,
    verify_start_create_volume,
    write_chunk,
    validate_network_address,
    GLUSTERFS_BASE_PORT,
    GLUSTERFS_MAX_PORT,
)

SECRET_KEY = os.getenv("JWT_SECRET")
ACCESS_TOKEN_EXPIRE_MINUTES = 60
API_PREFIX = "/api/management"
SECRET_FILE_NAME = ".env.keys"
RECOMMENDED_HOST_OS = ["Ubuntu 20", "Ubuntu 22", "RHEL 8", "RHEL 9"]
AVAILABLE_INPUTS = {}
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
LOGS_DIRECTORY = "./data/logs/management_server"
LOG_FILE_NAME = "management_server.log"
LOG_FILE_BACKUP_COUNT = 5
LOG_FILE_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOGS_DIRECTORY = "./data/logs/management_server"
LOG_FILE_NAME = "management_server.log"
ADMIN_ROLE = "admin"
SETTINGS_WRITE = "settings_write"
ME_ROLE = "me"
CERT_DIR = "./data/ssl_certs/mongodb_rabbitmq_certs/"
JWT_ALGORITH = "HS256"
JWT_ALGORITH_LIB_MAP = {
    "HS256": hashlib.sha256
}
DEFAULT_USER = "management"


def get_all_existed_env_variable(location=".env", override=True):
    """
    Read all existed environment variable from .env file.

    Args:
        location (str): The path to the .env file. Defaults to ".env".
        override (bool): Whether to override the existed environment
            variable. Defaults to True.
    """
    try:
        if not os.path.exists(location):
            return
        with open(location, "r") as f:
            if os.stat(location).st_size > 0:
                with open(f"{location}.{int(time.time())}", "w+") as backup:
                    for line in f.readlines():
                        backup.write(line)
                        key, value = line.split("=", 1)
                        if override or key not in AVAILABLE_INPUTS:
                            AVAILABLE_INPUTS[key] = value.strip()

        if AVAILABLE_INPUTS.get("HTTPS_PROXY"):
            AVAILABLE_INPUTS["CORE_HTTP_PROXY"] = AVAILABLE_INPUTS["HTTPS_PROXY"]
            AVAILABLE_INPUTS["CORE_HTTPS_PROXY"] = AVAILABLE_INPUTS["HTTPS_PROXY"]

            AVAILABLE_INPUTS.pop("HTTP_PROXY", None)
            AVAILABLE_INPUTS.pop("HTTPS_PROXY", None)
        if AVAILABLE_INPUTS.get("RABBITMQ_CUSTOM_CONF_PATH"):
            AVAILABLE_INPUTS.pop("RABBITMQ_CUSTOM_CONF_PATH", None)
    except Exception as e:
        raise Exception(f"Error occurred while getting env variables: {e}")


def move_secret_file(source, destination):
    """
    Move the secret file from the source to the destination.

    Args:
        source (str): The source path of the secret file.
        destination (str): The destination path of the secret file.

    Raises:
        Exception: If there is an error moving the secret file.
    """
    try:
        cmd = f"{SUDO_PREFIX} mv {source} {destination}".strip()
        set_directory_permission(source, cmd)
    except Exception as e:
        raise Exception(f"Error occurred while moving secret file. Error: {e}")


def retirable_execute_command(
    command,
    env=None,
    shell=False,
    input_data=None,
    max_retries=3,
    initial_delay=1,
    max_delay=5,
):
    """
    Execute a command with retries.

    Args:
        command (list): The command to execute with its arguments.
        env (dict): The environment variables to set.
        shell (bool): Whether to use the shell or not.
        input_data (str): The input data to provide to the command.
        max_retries (int): The maximum number of retries.
        initial_delay (int): The initial delay in seconds.
        max_delay (int): The maximum delay in seconds.

    Yields:
        dict: The messages from the command execution.

    Raises:
        Exception: If the command execution failed after all retries.
    """
    delay = initial_delay
    attempt = 0

    while attempt <= max_retries:
        attempt += 1
        return_code = 0
        for message in execute_command(
            command, env=env, shell=shell, input_data=input_data
        ):
            if message.get("type", "") == "returncode":
                return_code = message.get("code", 0)
                if return_code != 0:
                    break
            yield message

        if return_code == 0:
            break
        elif attempt <= max_retries:
            yield {
                "type": "retry",
                "message": f"Retrying in {delay} seconds...",
                "attempt": attempt,
            }
            time.sleep(delay)
            delay = min(delay * 2, max_delay)
        else:
            yield {"type": "returncode", "code": return_code}
            break


def get_load_average(processors):
    """
    Get the load average of the system.

    Args:
        processors (int): The number of processors in the system.

    Returns:
        tuple: A tuple containing the load average of the system and the HTTP status code.
    """
    if not processors:
        return {
            "load_avg_1min_percentage": None,
            "load_avg_5min_percentage": None,
            "load_avg_15min_percentage": None,
        }
    parts = []
    for result in execute_command("cat /proc/loadavg", shell=True):
        if result["type"] == "stdout":
            try:
                parts = result["message"].split()
                # The output is typically: '1.23 0.98 0.76 2/345 12345'
                # We only care about the first three numbers (1, 5, 15 min averages).
            except Exception as e:
                logger.error(
                    f"Parsing error in loadavg: {e}", extra={"node": utils.NODE_IP}
                )
        elif result["type"] == "stderr":
            logger.error(
                f"Error encountered while fetching cpu load from /proc/loadavg. {result['message']}",
                extra={"node": utils.NODE_IP},
            )
        elif result["type"] == "returncode" and result["code"] != 0:
            logger.error(
                f"Error encountered while fetching cpu load from /proc/loadavg. "
                f"Command exited with code {result['code']}",
                extra={"node": utils.NODE_IP},
            )
    try:
        return {
            "load_avg_1min_percentage": round((float(parts[0]) / processors) * 100, 2),
            "load_avg_5min_percentage": round((float(parts[1]) / processors) * 100, 2),
            "load_avg_15min_percentage": round((float(parts[2]) / processors) * 100, 2),
        }
    except Exception:
        return {
            "load_avg_1min_percentage": None,
            "load_avg_5min_percentage": None,
            "load_avg_15min_percentage": None,
        }


def get_cpu_count():
    """
    Get the number of processors in the system.

    Returns:
        int: The number of processors in the system.
    """
    resp = None
    for result in execute_command("nproc || getconf _NPROCESSORS_ONLN", shell=True):
        if result["type"] == "stdout":
            try:
                resp = int(result["message"])
            except (ValueError, TypeError):
                resp = None
        elif result["type"] == "stderr":
            logger.error(
                f"Error encountered while fetching processors count from nproc. {result['message']}",
                extra={"node": utils.NODE_IP},
            )
        elif result["type"] == "returncode" and result["code"] != 0:
            logger.error(
                f"Error encountered while fetching processors count from nproc. Process exited with {result['code']}.",
                extra={"node": utils.NODE_IP},
            )
    return resp


def get_memory_usage():
    """
    Get the memory usage of the system.

    Returns:
        dict: A dictionary containing the memory usage of the system.
    """
    meminfo = {}
    for result in execute_command("cat /proc/meminfo", shell=True):
        if result["type"] == "stdout":
            key, value = result["message"].split(":")
            meminfo[key.strip()] = int(value.strip().split()[0])
        elif result["type"] == "stderr":
            logger.error(
                f"Error encountered while fetching memory information from /proc/meminfo. "
                f"{result['message']}",
                extra={"node": utils.NODE_IP},
            )
        elif result["type"] == "returncode" and result["code"] != 0:
            logger.error(
                f"Error encountered while fetching memory information from /proc/meminfo. "
                f"Process exited with {result['code']}.",
                extra={"node": utils.NODE_IP},
            )
    try:
        total = meminfo.get("MemTotal")
        available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used = total - available
        return {
            "total_GB": round(total / 1024 / 1024, 2),
            "used_GB": round(used / 1024 / 1024, 2),
            "percent": round((used / total) * 100, 2),
        }
    except Exception:
        return {"total_GB": None, "used_GB": None, "percent": None}


def get_disk_usage():
    """
    Get the disk usage of the system.

    Returns:
        dict: A dictionary containing the disk usage of the system.
    """
    line_index = 0
    parts = []
    for result in execute_command("df -h /", shell=True):
        if result["type"] == "stdout":
            if line_index == 0:
                line_index += 1
                continue
            parts = re.split(r"\s+", result["message"])
        elif result["type"] == "stderr":
            logger.error(
                f"Error encountered while disk space. {result['message']}",
                extra={"node": utils.NODE_IP},
            )
        elif result["type"] == "returncode" and result["code"] != 0:
            logger.error(
                f"Error encountered while disk space. Process exited with {result['code']}.",
                extra={"node": utils.NODE_IP},
            )
    try:
        return {
            "total_GB": round(float(parts[1][:-1]), 2),
            "used_GB": round(float(parts[2][:-1]), 2),
            "available_GB": round(float(parts[3][:-1]), 2),
            "percent_used": round(float(parts[4].rstrip("%")), 2),
        }
    except Exception:
        return {
            "total_GB": None,
            "used_GB": None,
            "available_GB": None,
            "percent_used": None,
        }


def handle_http_errors(res):
    """
    Handle HTTP errors.

    Args:
        res (HTTPResponse): The HTTP response.

    Returns:
        bool: True if the request was successful, False otherwise.

    Raises:
        ClientExceptions: If the request was a client error.
        ServerExceptions: If the request was a server error.
    """
    status_code = res.code
    if status_code == 200:
        # raise ClientExceptions("Request Timeout Error.")
        return True

    # Client Errors
    elif status_code == 400:
        raise ClientExceptions("Bad Request Error.")
    elif status_code == 401:
        raise ClientExceptions("Unauthorized Error. Please ensure configured JWT_SECRET is same as Primary Node's JWT_SECRET before executing CE Setup.")
    elif status_code == 403:
        raise ClientExceptions("Forbidden Error.")
    elif status_code == 404:
        raise ClientExceptions("Not Found Error.")
    elif status_code == 408:
        raise ClientExceptions("Request Timeout Error.")

    # Server Errors
    # elif status_code == 500:
    #     raise ServerExceptions("Internal Server Error.")  ## 500 would be handled by the code.
    elif status_code == 502:
        raise ServerExceptions("Bad Gateway Error.")
    elif status_code == 503:
        raise ServerExceptions("Service Unavailable Error.")
    elif status_code == 504:
        raise ServerExceptions("Gateway Timeout Error.")
    return False


class SimpleAPIServer(BaseHTTPRequestHandler):
    """
    Handle HTTP requests.

    Args:
        - self (object): The class instance.
    """

    protocol_version = "HTTP/1.1"
    routes = {}

    @classmethod
    def route(cls, path, methods=["GET"], require_auth=True, stream=False, scopes=[ADMIN_ROLE]):
        """Define an API route decorator.

        Args:
            path (str): API path.
            methods (list): List of HTTP methods to support.
            require_auth (bool): If true, require authentication.
            stream (bool): If true, stream the response.
            scopes (list): Scopes defines which users can invoke the route.
                if any of the route scope aligns with the user scope, action is permitted.

        Returns:
            function: Decorated function.
        """

        def wrapper(func):
            for method in methods:
                new_path = path
                if not new_path.startswith(API_PREFIX):
                    new_path = API_PREFIX + path
                cls.routes[(new_path, method)] = (func, require_auth, stream, scopes)
            return func

        return wrapper

    def do_GET(self):
        """
        Handle HTTP GET requests.

        Args:
            self (object): The class instance.
        """
        self.handle_request("GET")

    def do_POST(self):
        """
        Handle HTTP POST requests.

        Args:
            self (object): The class instance.

        """
        self.handle_request("POST")

    def do_PUT(self):
        """
        Handle HTTP PUT requests.

        Args:
            self (object): The class instance.

        """
        self.handle_request("PUT")

    def do_PATCH(self):
        """
        Handle HTTP PATCH requests.

        Args:
            self (object): The class instance.

        """
        self.handle_request("PATCH")

    def do_DELETE(self):
        """
        Handle HTTP DELETE requests.

        Args:
            self (object): The class instance.

        Raises:
            HTTPException: If the request was not successful.
        """
        self.handle_request("DELETE")

    def log_message(self, format, *args):
        """Log an arbitrary message.

        This is used by all other logging functions.  Override
        it if you have specific logging wishes.

        The first argument, FORMAT, is a format string for the
        message to be logged.  If the format string contains
        any % escapes requiring parameters, they should be
        specified as subsequent arguments (it's just like
        printf!).

        The client ip and current date/time are prefixed to
        every message.

        Unicode control characters are replaced with escaped hex
        before writing the output to stderr.

        """
        # overridden.
        def strip_control_chars(s):
            return "".join(c for c in s if c in string.printable)

        message = format % args
        clean_msg = strip_control_chars(message)
        logger.info(
            f"{self.address_string()} - {clean_msg}",
            extra={"node": utils.NODE_IP},
        )

    def end_cors_headers(self):
        """Add CORS headers to response."""
        # Add CORS headers
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header(
            "Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, PATCH, OPTIONS"
        )
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        """
        Handle HTTP OPTIONS requests.

        This is used for CORS.

        """
        self.send_response(200, "ok")
        self.end_cors_headers()

    def handle_request(self, method):
        """
        Handle a request.

        Args:
            method (str): HTTP method.

        Raises:
            HTTPException: If the request was not successful.
        """
        try:
            path = urlparse(self.path).path
            route = self.routes.get((path, method))
            if route:
                handler, require_auth, stream, scopes = route
                if require_auth and not self.is_authenticated(scopes):
                    response = json.dumps({"detail": "Unauthorized"}).encode()
                    self.send_response(401)
                    self.send_header("Content-type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                    self.wfile.flush()
                    return
                else:
                    if stream:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Transfer-Encoding", "chunked")
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        try:
                            return handler(self)
                        except Exception as e:
                            logger.error(
                                f"Error handling request for {self.path}. Error: {str(e)} "
                                f"Traceback: {traceback.format_exc()}",
                                extra={"node": utils.NODE_IP},
                            )
                            write_chunk(
                                self.wfile,
                                f"End: error handling request for {self.path}. Error: {str(e)}\n",
                            )
                            return
                    try:
                        response, status_code = handler(self)
                        response = json.dumps(response).encode()
                    except Exception as e:
                        logger.error(
                            f"Error handling request for {self.path}. Error: {str(e)} "
                            f"Traceback: {traceback.format_exc()}",
                            extra={"node": utils.NODE_IP},
                        )
                        response = json.dumps(
                            {
                                "details": f"Error handling request for {self.path}. Error: {str(e)}"
                            }
                        ).encode()
                        status_code = 500
                    self.send_response(status_code)
                    self.send_header("Content-type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                    self.wfile.flush()
                    return
            else:
                response = json.dumps({"detail": "Not found"}).encode()
                self.send_response(404)
                self.send_header("Content-type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
                self.wfile.flush()
                return
        except Exception as e:
            logger.error(
                f"Error handling request for {self.path}. Error: {str(e)} "
                f"Traceback: {traceback.format_exc()}",
                extra={"node": utils.NODE_IP},
            )
            return

    def is_authenticated(self, scopes):
        """
        Check if the request is authenticated.

        Returns:
            bool: True if authenticated, False otherwise.
        """
        global SECRET_KEY
        if SECRET_KEY is None:
            config = read_config_file(CONFIG_FILE_PATH)
            if config.get("JWT_SECRET") is None:
                SECRET_KEY = os.getenv("JWT_SECRET")
            else:
                SECRET_KEY = config.get("JWT_SECRET")
        if SECRET_KEY is None or SECRET_KEY == "":
            logger.error(
                "JWT_SECRET is not set in the environment variable or config file.",
                extra={"node": utils.NODE_IP},
            )
            raise Exception(
                "JWT_SECRET is not set in the environment variable or config file."
            )
        auth_header = self.headers.get("Authorization")
        if auth_header and (
            auth_header.startswith("Bearer ") or auth_header.startswith("bearer ")
        ):
            token = auth_header.split(" ")[1]
            return self.verify_token(token, scopes)
        return False

    def verify_token(self, token, scopes):
        """
        Verify if the given token is valid.

        Args:
            token (str): The JWT token to verify.

        Returns:
            bool: True if the token is valid, False otherwise.

        Raises:
            Exception: If JWT_SECRET is not set in the environment variable or config file.
        """
        try:
            header_b64, payload, signature, message = extract_payload_signature(token)
            if not header_b64 or not payload or not signature or not message:
                raise ValueError("Token does not have valid structure.")

            # Verify signature
            expected_sig = hmac.new(
                SECRET_KEY.encode(), message, JWT_ALGORITH_LIB_MAP[JWT_ALGORITH]
            ).digest()

            if not hmac.compare_digest(signature, expected_sig):
                raise ValueError("Invalid Signature")

            # Check expiry
            if "exp" in payload and isinstance(payload["exp"], int):
                if int(datetime.now(UTC).timestamp()) > payload["exp"]:
                    raise ValueError("Token has expired")
            else:
                raise ValueError("Token does not have valid expiry details.")

            # Check scopes
            if not isinstance(scopes, list):
                raise ValueError("The `scopes` should be a valid list.")

            if len(scopes) > 0:
                if "scopes" not in payload:
                    raise ValueError("Token payload does not have required fields.")

                # If any of the set scopes align with the scopes required by route it will be allowed.
                if len(set(scopes) & (set(payload.get("scopes", [])))) < 1:
                    raise ValueError("Token does not have required scopes")

            ALLOWED_TYPES = ["user-access", "service-access"]
            if "type" not in payload:
                raise ValueError("Token payload does not have required fields.")
            elif payload.get("type", "") not in ALLOWED_TYPES:
                raise ValueError("Token does not have valid access type.")

            return True
        except Exception as e:
            logger.error(
                f"Token verification error: {e}. Traceback: {traceback.format_exc()}",
                extra={"node": utils.NODE_IP},
            )
            return False


def extract_payload_signature(token):
    """
    Extract the payload and signature from the token.

    Args:
        token (str): The JWT token to extract the payload and signature from.

    Returns:
        tuple: A tuple containing the header, payload, signature, and message.
    """
    if len(token.split(".")) != 3:
        return None, None, None, None
    header_b64, payload_b64, signature_b64 = token.split(".")

    def base64url_decode(input_str: str) -> bytes:
        padding = "=" * (-len(input_str) % 4)
        return base64.urlsafe_b64decode(input_str + padding)

    # Decode
    payload = json.loads(base64url_decode(payload_b64))
    signature = base64url_decode(signature_b64)
    message = message = f"{header_b64}.{payload_b64}".encode()
    return header_b64, payload, signature, message


def create_token(auth_header):
    """
    Generate a JWT token for the given username.

    Args:
        auth_header (str): Request token to generate token for.

    Returns:
        str: The generated JWT token.

    Raises:
        Exception: If JWT_SECRET is not set in the environment variable or config file.
    """
    try:
        if not auth_header or not isinstance(auth_header, str) or len(auth_header.split(" ")) < 2:
            return None

        _, payload, _, _ = extract_payload_signature(auth_header.split(" ")[1])
        if not payload:
            return None

        header_dict = {"alg": "HS256", "typ": "JWT"}
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(header_dict).encode('utf-8')
        ).decode().rstrip('=')

        payload_dict = {
            "username": payload.get("username", DEFAULT_USER),
            "scopes": payload.get("scopes", []),
            "type": "service-access",
            "exp": int((datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        }
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload_dict).encode('utf-8')
        ).decode().rstrip('=')
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        signature_binary = hmac.new(
            SECRET_KEY.encode(),
            signing_input,
            JWT_ALGORITH_LIB_MAP[JWT_ALGORITH],
        ).digest()
        encoded_signature = base64.urlsafe_b64encode(signature_binary).decode().rstrip('=')
        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"
    except Exception as e:
        logger.error(f"encountered error while creating token: {e} {traceback.format_exc()}")
        return None


def get_certs_locations():
    """Get the locations of the server certificate, server private key, and client CA certificate."""
    server_cert = CERT_DIR + 'tls_cert.crt'  # Server certificate
    server_key = CERT_DIR + 'tls_cert_key.key'   # Server private key
    client_ca = CERT_DIR + 'tls_cert_ca.crt'  # CA certificate that signed client certificates
    if not os.path.exists(server_cert) or not os.path.exists(server_key) or not os.path.exists(client_ca):
        raise Exception("SSL certificates not found.")

    return server_cert, server_key, client_ca


def run(server_class=HTTPServer, handler_class=SimpleAPIServer):
    """
    Run the API server.

    Args:
        server_class (class): Server class to use, defaults to HTTPServer.
        handler_class (class): Handler class to use, defaults to SimpleAPIServer.
    """
    server_cert, server_key, client_ca = get_certs_locations()

    if not os.path.exists(server_cert) or not os.path.exists(server_key) or not os.path.exists(client_ca):
        raise Exception("Certificates not found.")

    port = int(os.getenv("CE_MANAGEMENT_PORT", 8000))
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)

    # Improved SSL context configuration
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.load_verify_locations(cafile=client_ca)
    context.check_hostname = False

    httpd.socket = context.wrap_socket(
        httpd.socket,
        server_side=True,
        do_handshake_on_connect=True
    )

    logger.info(f"Server running at https://{server_address[0]}:{server_address[1]}")
    httpd.serve_forever()


# --- Define Endpoints Below ---


@SimpleAPIServer.route("/", methods=["GET"], require_auth=False, scopes=[])
def home(handler):
    """Display the management API server homepage.

    Returns:
        tuple: A tuple containing the response data and status. The response data is a dictionary with the key "detail"
            containing a welcome message.
    """
    return {"detail": "Welcome to the Cloud Exchange API Server!"}, 200


@SimpleAPIServer.route("/update-env", methods=["PUT"], scopes=[ADMIN_ROLE, SETTINGS_WRITE])
def update_env(handler, update_data=None, env_file=None):
    """
    Update environment variables.

    Args:
        update_data (dict): The data to update.
        env_file (str, optional): The path to the environment file. Defaults to None.

    Returns:
        tuple: A tuple containing the response data and status. The response data is a dictionary with the key "detail"
            containing a success message and the key "errors" containing a dictionary with the keys being names of the
            environment variables that failed to update.

    Raises:
        Exception: If the environment file is not found.
    """
    if update_data is None:
        try:
            content_length = int(handler.headers.get("Content-Length", 0))
            body = handler.rfile.read(content_length).decode()
            update_data = json.loads(body)
        except json.JSONDecodeError:
            return {"detail": "Invalid request"}, 400

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return {"details": error_msg}, 500

    should_proceed = False
    errors = {}
    for key, value in update_data.items():
        if key in UPDATES_ALLOWED_ON_ENV:
            if key == "MAINTENANCE_PASSWORD":
                if (
                    ("\\" in value)
                    or ("/" in value)
                    or ("'" in value)
                    or ('"' in value)
                    or (" " in value)
                ):
                    errors[key] = "Invalid value for maintenance password"
            should_proceed = True

    if not should_proceed or errors:
        return {"detail": "Invalid data provided", "errors": errors}, 400
    for key, value in update_data.items():
        if key in UPDATES_ALLOWED_ON_ENV:
            if key == "MAINTENANCE_PASSWORD":
                if (
                    ("\\" in value)
                    or ("/" in value)
                    or ("'" in value)
                    or ('"' in value)
                    or (" " in value)
                ):
                    return {"detail": "Invalid value for environment variable"}, 400

    if env_file:
        env_file_path = env_file
    elif (
        not env_file
        and AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
        or AVAILABLE_INPUTS.get("LOCATION", "") != ".env.keys"
    ):
        env_file_path = os.path.join(
            os.path.dirname(AVAILABLE_INPUTS.get("LOCATION", "")), ".env"
        )
    else:
        env_file_path = ".env"
    try:
        with open(env_file_path, "r+") as f:
            to_remove = set()
            try:
                fcntl.flock(f, fcntl.LOCK_EX)
                env_data = f.readlines()
                for key, value in update_data.items():
                    if key not in UPDATES_ALLOWED_ON_ENV:
                        continue
                    if key == "MAINTENANCE_PASSWORD":
                        passwords = {
                            "MAINTENANCE_PASSWORD": f"'{value}'",
                            "MAINTENANCE_PASSWORD_ESCAPED": urllib.parse.quote_plus(
                                value
                            ),
                        }
                        secret_location = get_secret_location(AVAILABLE_INPUTS)
                        if os.path.exists(secret_location):
                            new_path = f"{secret_location}.{int(time.time())}"
                            move_secret_file(secret_location, new_path)
                        create_secret_file(passwords, secret_location)
                        continue
                    for i, line in enumerate(env_data):
                        if (
                            line.startswith(key + "=")
                            and value == ""
                            and (key not in ["CORE_HTTP_PROXY", "CORE_HTTPS_PROXY"])
                        ):
                            to_remove.add(i)
                        elif line.startswith(key + "="):
                            env_data[i] = f"{key}={value}\n"
                            break
                    else:
                        if value != "":
                            env_data.append(f"{key}={value}\n")
                for i in sorted(to_remove, reverse=True):
                    del env_data[i]
                f.seek(0)
                f.writelines(env_data)
                f.truncate()
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error updating env file: {e}", extra={"node": utils.NODE_IP})
        return {"detail": f"Error updating env file {str(e)}"}, 500
    return {"detail": "Env file updated"}, 200


@SimpleAPIServer.route("/start-ce", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def start_ce(handler, should_end_stream=True, ip=None, as_api=True):
    """
    Start the Cloud Exchange service.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        should_end_stream (bool, optional): Whether to end the stream after executing the command. Defaults to True.
        ip (str, optional): The IP address of the node. Defaults to None.
        as_api (bool, optional): Whether the command is being executed as an API. Defaults to True.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        Exception: If an exception occurs while executing the command.
    """
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        write_chunk(handler.wfile, "End: Error loading environment variables.")
        end_stream(handler)
        return {"details": error_msg}, 500
    if as_api:
        try:
            content_length = int(handler.headers.get("Content-Length", 0))
            body = handler.rfile.read(content_length).decode()
            data = json.loads(body)
            ip = data.get("node_ip").strip()
        except (json.JSONDecodeError, AttributeError):
            write_chunk(handler.wfile, "End: Invalid Request.")
            end_stream(handler)
            return {"detail": "Invalid request"}, 400

        if not ip:
            write_chunk(handler.wfile, "End: Node IP not provided.")
            end_stream(handler)
            return {"detail": "Node IP not provided"}, 400
        elif not validate_network_address(ip):
            write_chunk(handler.wfile, "End: Invalid Node IP.")
            end_stream(handler)
            return {"detail": "Invalid Node IP"}, 400
    elif not ip:
        ip = utils.NODE_IP

    if (
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE") is not None
        and ip != AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
    ) or ip != utils.NODE_IP:
        logger.info(
            f"Starting Cloud Exchange on Node {ip}", extra={"node": utils.NODE_IP}
        )
        try:
            for response_chunk in check_management_server(
                handler=handler,
                endpoint="/api/management/start-ce",
                node_ip=ip,
                method="POST",
                protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
                should_stream=True,
                payload={"node_ip": ip},
            ):
                if response_chunk[:3].upper() == "END":
                    raise Exception(response_chunk)
                else:
                    write_chunk(handler.wfile, response_chunk, node_ip=ip)
            write_chunk(handler.wfile, "Info: Cloud Exchange started.\n")
        except Exception as e:
            write_chunk(
                handler.wfile,
                f"End: Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}\n",
            )
            return {
                "detail": f"Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}"
            }, 500
        finally:
            end_stream(handler=handler, should_end_stream=should_end_stream)
    else:
        logger.info("Starting the local Cloud Exchange.", extra={"node": utils.NODE_IP})
        command = f"{SUDO_PREFIX} ./start"
        command = command.strip().split(" ")
        response = execute_command_with_logging(
            command,
            handler,
            should_end_stream=should_end_stream,
            message="starting Cloud Exchange",
        )
        if response[1] != 200:
            end_stream(handler=handler, should_end_stream=should_end_stream)
            return response
        write_chunk(handler.wfile, "Info: Cloud Exchange started.\n")
    return {"detail": "Cloud Exchange started"}, 200


@SimpleAPIServer.route("/stop-ce", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def stop_ce(handler, should_end_stream=True, ip=None, as_api=True):
    """
    Stop the Cloud Exchange service.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        should_end_stream (bool, optional): Whether to end the stream after executing the command. Defaults to True.
        ip (str, optional): The IP address of the node. Defaults to None.
        as_api (bool, optional): Whether to execute the command as an API. Defaults to True.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.
    """
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        write_chunk(handler.wfile, "End: Error loading environment variables.")
        end_stream(handler)
        return {"details": error_msg}, 500
    if as_api:
        try:
            content_length = int(handler.headers.get("Content-Length", 0))
            body = handler.rfile.read(content_length).decode()
            data = json.loads(body)
            ip = data.get("node_ip").strip()
        except (json.JSONDecodeError, AttributeError):
            write_chunk(handler.wfile, "End: Invalid Request.")
            end_stream(handler)
            return {"detail": "Invalid request"}, 400
        if not ip:
            write_chunk(handler.wfile, "End: Node IP not provided.")
            end_stream(handler)
            return {"detail": "Node IP not provided"}, 400
        elif not validate_network_address(ip):
            write_chunk(handler.wfile, "End: Invalid Node IP.")
            end_stream(handler)
            return {"detail": "Invalid Node IP"}, 400
    elif not ip:
        ip = utils.NODE_IP

    if (
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE") is not None
        and ip != AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
    ) or ip != utils.NODE_IP:
        logger.info(
            f"Stopping Cloud Exchange on Node {ip}", extra={"node": utils.NODE_IP}
        )
        try:
            for response_chunk in check_management_server(
                handler=handler,
                endpoint="/api/management/stop-ce",
                node_ip=ip,
                method="POST",
                protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
                should_stream=True,
                payload={"node_ip": ip},
            ):
                if response_chunk[:3].upper() == "END":
                    raise Exception(response_chunk)
                else:
                    write_chunk(handler.wfile, response_chunk, node_ip=ip)
            write_chunk(handler.wfile, "Info: Cloud Exchange stopped.\n")
        except Exception as e:
            write_chunk(
                handler.wfile,
                f"End: Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}\n",
            )
            return {
                "detail": f"Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}"
            }, 500
        finally:
            end_stream(handler=handler, should_end_stream=should_end_stream)
    else:
        logger.info("Stopping the local Cloud Exchange.", extra={"node": utils.NODE_IP})
        command = f"{SUDO_PREFIX} ./stop"
        command = command.strip().split(" ")
        response = execute_command_with_logging(
            command,
            handler,
            should_end_stream=should_end_stream,
            message="stopping Cloud Exchange",
        )
        if response[1] != 200:
            end_stream(handler=handler, should_end_stream=should_end_stream)
            return response
        write_chunk(handler.wfile, "Info: Cloud Exchange stopped.\n")
    return {"detail": "Cloud Exchange stopped"}, 200


@SimpleAPIServer.route("/historical-logs", methods=["GET"], stream=True, scopes=[ADMIN_ROLE])
def stream_from_logfile(handler):
    """
    Stream the historical logs from the log file.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.
    """
    log_path = os.path.join(LOGS_DIRECTORY, LOG_FILE_NAME)
    try:
        with open(log_path, "r") as f:
            for _, line in enumerate(f):
                write_chunk(handler.wfile, line, skip_log=True)
    except Exception as e:
        write_chunk(handler.wfile, "End: Error reading log file.")
        logger.error(f"Error reading log file: {e}", extra={"node": utils.NODE_IP})
        return {"detail": f"Error reading log file: {str(e)}"}, 500
    finally:
        end_stream(handler=handler)
    return {"detail": "Log file streamed"}, 200


@SimpleAPIServer.route("/restart-ce", stream=True, methods=["POST"], scopes=[ADMIN_ROLE])
def restart_ce(handler, as_api=True):
    """
    Restart Cloud Exchange.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        as_api (bool, optional): Whether to execute the command as an API. Defaults to True.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.
    """
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        write_chunk(handler.wfile, "End: Error loading environment variables.")
        end_stream(handler)
        return {"details": error_msg}, 500
    ip = ""
    if as_api:
        try:
            content_length = int(handler.headers.get("Content-Length", 0))
            body = handler.rfile.read(content_length).decode()
            data = json.loads(body)
            ip = data.get("node_ip").strip()
        except (json.JSONDecodeError, AttributeError):
            write_chunk(handler.wfile, "End: Invalid Request.")
            end_stream(handler)
            return {"detail": "Invalid request"}, 400
        if not ip:
            write_chunk(handler.wfile, "End: Node IP not provided.")
            end_stream(handler)
            return {"detail": "Node IP not provided"}, 400
        elif not validate_network_address(ip):
            write_chunk(handler.wfile, "End: Invalid Node IP.")
            end_stream(handler)
            return {"detail": "Invalid Node IP"}, 400
    else:
        ip = utils.NODE_IP

    try:
        write_chunk(handler.wfile, "Info: Restarting Cloud Exchange.\n")
        response = stop_ce(
            handler=handler, should_end_stream=False, as_api=False, ip=ip
        )
        if response[1] != 200:
            end_stream(handler=handler)
            return response
        response = start_ce(
            handler=handler, should_end_stream=False, as_api=False, ip=ip
        )
        if response[1] != 200:
            end_stream(handler=handler)
            return response
        write_chunk(handler.wfile, "Info: Cloud Exchange restarted.\n")
    except Exception as e:
        logger.error(
            f"Error Restarting the Cloud Exchange: {e}", extra={"node": utils.NODE_IP}
        )
        write_chunk(
            handler.wfile, f"End: Error Restarting the Cloud Exchange: {str(e)}\n"
        )
        end_stream(handler=handler)
        return {"detail": f"Error Restarting the Cloud Exchange: {str(e)}"}, 500
    finally:
        end_stream(handler=handler)
    return {"detail": "Restarted Cloud Exchange successfully."}, 200


def read_config_file(file_path):
    """
    Read a configuration file and returns the key-value pairs.

    Args:
        file_path (str): The path to the configuration file.

    Returns:
        dict: A dictionary containing the key-value pairs from the configuration file.

    Raises:
        Exception: If there is an error reading the configuration file.
    """
    config = {}
    if not os.path.exists(file_path):
        logger.warning(
            f"Config file '{file_path}' does not exist.", extra={"node": utils.NODE_IP}
        )
        return config

    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    except Exception as e:
        logger.error(
            f"Error reading config file '{file_path}': {e}",
            extra={"node": utils.NODE_IP},
        )

    return config


@SimpleAPIServer.route("/update-config", methods=["POST"], scopes=[ADMIN_ROLE])
def update_config_file(handler, keys_to_update=None):
    """
    Update a configuration file with the provided key-value pairs.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        keys_to_update (dict): The key-value pairs to update in the configuration file.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        HTTPException: If there is an error updating the configuration file.
    """
    if keys_to_update is None:
        try:
            content_length = int(handler.headers.get("Content-Length", 0))
            body = handler.rfile.read(content_length).decode()
            keys_to_update = json.loads(body)
        except json.JSONDecodeError:
            return {"detail": "Invalid request"}, 400

    try:
        update_cloudexchange_config(updated_config=keys_to_update)
    except Exception as e:
        return {
            "detail": f"Error encountered while updating config file. Error: {str(e)}."
        }, 500
    return {"detail": "Config file updated successfully."}, 200


@SimpleAPIServer.route("/get-config", methods=["GET"], scopes=[ADMIN_ROLE])
def get_config(handler):
    """
    Update a configuration file with the provided key-value pairs.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        HTTPException: If there is an error updating the configuration file.
    """
    try:
        config = read_config_file(CONFIG_FILE_PATH)
        return config, 200
    except Exception as e:
        return {
            "detail": f"Error encountered while reading config file. Error: {str(e)}."
        }, 500


@SimpleAPIServer.route("/install-gluster", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def install_gluster_route(handler):
    """
    Install glusterfs on a remote server.

    Args:
        handler: The web server request handler.

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.

    Raises:
        HTTPException: If there is an error installing GlusterFS.
    """
    try:
        content_length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(content_length).decode()
        data = json.loads(body)
    except json.JSONDecodeError:
        write_chunk(handler.wfile, "End: Invalid Request.")
        end_stream(handler=handler, should_end_stream=True)
        return {"detail": "Invalid request"}, 400

    if not data.get("shared_directory_path"):
        write_chunk(
            handler.wfile, "End: Please provide a valid shared directory path\n"
        )
        end_stream(handler=handler, should_end_stream=True)
        return {"detail": "Please provide a valid shared directory path"}, 400
    else:
        shared_directory_path = data.get("shared_directory_path")
    glusterfs_base_port = data.get("glusterfs_base_port", GLUSTERFS_BASE_PORT)
    glusterfs_max_port = data.get("glusterfs_max_port", GLUSTERFS_BASE_PORT)

    return install_gluster(
        handler=handler,
        shared_directory_path=shared_directory_path,
        should_end_stream=True,
        glusterfs_base_port=glusterfs_base_port,
        glusterfs_max_port=glusterfs_max_port,
    )


@SimpleAPIServer.route("/ensure-volume", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def ensure_volume_mounted_route(handler):
    """
    Ensure that the glusterfs volume is mounted.

    Args:
        handler: The web server request handler.

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.

    Raises:
        HTTPException: If there is an error mounting the volume.
    """
    try:
        content_length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(content_length).decode()
        data = json.loads(body)
    except json.JSONDecodeError:
        write_chunk(handler.wfile, "End: Invalid Request.")
        end_stream(handler=handler, should_end_stream=True)
        return {"detail": "Invalid request"}, 400
    if data.get("shared_directory_path") and data.get("current_node_ip"):
        shared_directory_path = data.get("shared_directory_path")
        current_node_ip = data.get("current_node_ip")
    else:
        write_chunk(
            handler.wfile,
            "End: Please provide a valid shared directory path and current node ip.\n",
        )
        end_stream(handler=handler, should_end_stream=True)
        return {
            "detail": "Please provide a valid shared directory path and current node ip."
        }, 400

    return ensure_volume_mounted(
        handler=handler,
        shared_directory_path=shared_directory_path,
        current_node_ip=current_node_ip,
        should_end_stream=True,
    )


@SimpleAPIServer.route("/setup", methods=["GET"], stream=True, scopes=[ADMIN_ROLE])
def setup(handler, should_end_stream=True, flags="", is_api=True):
    """
    Execute the setup script for Cloud Exchange.

    This endpoint is used to setup the Cloud Exchange.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        should_end_stream (bool, optional): Whether to end the stream after executing the command. Defaults to True.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.
    """
    write_chunk(handler.wfile, "Info: Executing setup.\n")
    if is_api:
        try:
            parsed_url = urlparse(handler.path)
            query_params = parse_qs(parsed_url.query)
            flags = "".join(query_params.get("flags", [""]))
        except Exception:
            flags = ""

    command = f"{SUDO_PREFIX} ./setup {flags}"
    command = command.strip().split(" ")
    response = execute_command_with_logging(
        command,
        handler,
        should_end_stream=should_end_stream,
        message="setting up Cloud Exchange",
    )
    if response[1] != 200:
        end_stream(handler=handler, should_end_stream=should_end_stream)
        return response
    write_chunk(handler.wfile, "Info: Setup completed successfully.\n")
    return {"detail": "Cloud Exchange Setup completed."}, 200


@SimpleAPIServer.route("/enable-ha", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def enable_ha(handler):
    """
    Enable High Availability for Cloud Exchange.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        HTTPException: If there is an error enabling HA.
    """
    shared_base_directory = "/opt/shared"
    try:
        content_length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(content_length).decode()
        data = json.loads(body)
        current_node_ip = data.get("node_ip").strip()
    except (json.JSONDecodeError, AttributeError):
        write_chunk(handler.wfile, "End: Invalid Request.")
        end_stream(handler=handler)
        return {"detail": "Invalid request"}, 400

    if not current_node_ip or current_node_ip == "":
        write_chunk(handler.wfile, "End: Node IP not provided.")
        end_stream(handler=handler)
        return {"detail": "Node IP not provided"}, 400
    elif not validate_network_address(current_node_ip):
        write_chunk(handler.wfile, "End: Invalid Node IP.")
        end_stream(handler=handler)
        return {"detail": "Invalid Node IP"}, 400

    utils.NODE_IP = current_node_ip

    write_chunk(handler.wfile, "Info: Validating Prerequisites for HA\n")
    response = setup(
        handler=handler,
        should_end_stream=False,
        flags="--check-prerequisites HA",
        is_api=False,
    )
    if response[1] != 200:
        write_chunk(
            handler.wfile,
            (
                "Info: Error encountered while validating the Prerequisites for HA, "
                "please ensure the requirements are met.\n"
            ),
        )
        end_stream(handler)
        return response
    write_chunk(handler.wfile, "Info: Validation successful for prerequisites.\n")

    configs = read_config_file(CONFIG_FILE_PATH)
    try:
        glusterfs_base_port = int(configs.get("GLUSTERFS_BASE_PORT", GLUSTERFS_BASE_PORT))
        glusterfs_max_port = int(configs.get("GLUSTERFS_MAX_PORT", GLUSTERFS_MAX_PORT))
    except Exception:
        glusterfs_base_port = GLUSTERFS_BASE_PORT
        glusterfs_max_port = GLUSTERFS_MAX_PORT

    response = install_gluster(
        handler=handler,
        shared_directory_path=shared_base_directory,
        should_end_stream=False,
        glusterfs_base_port=glusterfs_base_port,
        glusterfs_max_port=glusterfs_max_port,
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response

    response = verify_start_create_volume(
        handler=handler, current_node_ip=current_node_ip
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response

    response = ensure_volume_mounted(
        handler=handler,
        shared_directory_path=shared_base_directory,
        current_node_ip=current_node_ip,
        should_end_stream=False,
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response

    # stop Cloud Exchange
    write_chunk(handler.wfile, "Info: Stopping Cloud Exchange\n")
    response = stop_ce(handler=handler, should_end_stream=False, as_api=False)
    if response[1] != 200:
        end_stream(handler=handler)
        return response
    write_chunk(handler.wfile, "Info: Stopped Cloud Exchange\n")

    # update the config file.
    write_chunk(handler.wfile, "Info: Updating the Cloud Exchange config file.\n")
    get_all_existed_env_variable(location=".env", override=True)
    response = update_config_file(
        handler=handler,
        keys_to_update={
            "HA_ENABLED": True,
            "HA_CURRENT_NODE": current_node_ip,
            "HA_PRIMARY_NODE_IP": current_node_ip,
            "HA_NFS_DATA_DIRECTORY": f"{shared_base_directory}/data",
            "HA_IP_LIST": f"{current_node_ip}",
            "JWT_SECRET": AVAILABLE_INPUTS["JWT_SECRET"],
        },
    )
    if response[1] != 200:
        end_stream(handler)
        return response

    # move the custom plugins to ha dir.
    write_chunk(
        handler.wfile,
        "Info: Moving plugins, repos, and custom plugins to HA directory.\n",
    )
    command = f"{SUDO_PREFIX} cp -r ./data/custom_plugins ./data/plugins ./data/repos {shared_base_directory}/data/"
    command = command.strip().split(" ")
    response = execute_command_with_logging(
        command,
        handler,
        message="moving plugins, repos, and custom plugins to shared directory",
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response
    write_chunk(handler.wfile, "Info: Moved custom plugins to shared directory.\n")

    # move the custom plugins to ha dir.
    write_chunk(handler.wfile, "Info: Moving custom certs and ssl certs to shared directory.\n")
    command = (
        f"{SUDO_PREFIX} mkdir -p {shared_base_directory}/data/config/ca_certs &&"
        f"{SUDO_PREFIX} cp -r ./data/ca_certs/ ./data/ssl_certs/ {shared_base_directory}/data/config/"
    )
    for command in command.split("&&"):
        command = command.strip().split(" ")
        response = execute_command_with_logging(
            command, handler, message="moving custom certs and ssl certs to shared directory"
        )
        if response[1] != 200:
            end_stream(handler=handler)
            return response
    write_chunk(handler.wfile, "Info: Moved custom certs and ssl certs to shared directory.\n")

    response = setup(
        handler=handler,
        should_end_stream=False,
        flags="--avoid-service-restart",
        is_api=False,
    )
    if response[1] != 200:
        write_chunk(
            handler.wfile,
            "Info: Error encountered while executing setup, re-starting Cloud Exchange.\n",
        )
        response = start_ce(handler=handler, should_end_stream=False, as_api=False)
        if response[1] != 200:
            end_stream(handler=handler)
            return response
        write_chunk(handler.wfile, "Info: Existing Cloud Exchange started.\n")
        end_stream(handler)
        return response

    # start ha single node.
    write_chunk(handler.wfile, "Info: Starting Cloud Exchange cluster.\n")
    response = start_ce(handler=handler, should_end_stream=False, as_api=False)
    if response[1] != 200:
        end_stream(handler=handler)
        return response
    write_chunk(handler.wfile, "Info: Cloud Exchange cluster started.\n")
    end_stream(handler=handler)
    logger.info("Cloud Exchange cluster started", extra={"node": utils.NODE_IP})
    return {"detail": "Cloud Exchange cluster started."}, 200


def load_environment_from_multiple_sources(handler=None):
    """Load environment variables from both .env and the location specified in AVAILABLE_INPUTS.

    Returns (success, error_message) tuple.
    """
    try:
        get_all_existed_env_variable(location=".env", override=True)
    except Exception as e:
        error_msg = str(e)
        return False, error_msg

    if (
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
        or AVAILABLE_INPUTS.get("LOCATION", "") != ".env.keys"
    ):
        try:
            location = AVAILABLE_INPUTS["LOCATION"]
            directory = os.path.dirname(location.rstrip("/"))
            env_path = os.path.join(directory, ".env")

            get_all_existed_env_variable(location=env_path, override=True)
        except Exception as e:
            error_msg = (
                f"Error encountered while fetching environment details. Error: {e}"
            )
            if handler:
                write_chunk(handler.wfile, f"End: {error_msg}\n")
                end_stream(handler=handler)
            return False, error_msg

    return True, None


@SimpleAPIServer.route("/node-details", methods=["GET"], scopes=[ME_ROLE])
def node_details(handler):
    """
    Get node details.

    Args:
        handler (Handler): The handler object.

    Returns:
        dict: A dictionary containing the host machine's IP address.
        The dictionary will have a single key "detail" with the IP address as the value.
    """
    response = get_node_ip()  # updates the utils.NODE_IP to node ip.
    if response[1] != 200:
        return response

    AVAILABLE_INPUTS.pop("HA_ENABLED", None)  # reset the available inputs to get fresh data.
    AVAILABLE_INPUTS.pop("HA_IP_LIST", None)
    AVAILABLE_INPUTS.pop("HA_CURRENT_NODE", None)
    AVAILABLE_INPUTS.pop("HA_PRIMARY_NODE_IP", None)

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return {"details": error_msg}, 500

    if (
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
        and isinstance(AVAILABLE_INPUTS.get("HA_CURRENT_NODE"), str)
        and len(AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()) > 0
        and utils.NODE_IP != AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()
    ):
        utils.NODE_IP = AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()

    response = {
        "HA_IP_LIST": AVAILABLE_INPUTS.get("HA_IP_LIST", None),
        "HA_CURRENT_NODE": AVAILABLE_INPUTS.get("HA_CURRENT_NODE", utils.NODE_IP),
        "HA_PRIMARY_NODE_IP": AVAILABLE_INPUTS.get("HA_PRIMARY_NODE_IP", None),
        "HA_ENABLED": AVAILABLE_INPUTS.get("HA_ENABLED", None),
    }
    return {"details": response}, 200


def check_management_server(
    node_ip,
    handler,
    endpoint,
    method,
    protocol="https",
    should_stream=False,
    payload=None,
    params=None,
):
    """
    Check the management server.

    Args:
        node_ip (str): The IP address of the host machine.
        handler (Handler): The handler object.
        endpoint (str): The endpoint to hit.
        method (str): The HTTP method to use.
        protocol (str): The protocol to use. Defaults to "http".
        should_stream (bool): A boolean indicating whether to stream the response.
        payload (str): The payload to send with the request.

    Returns:
        Response: The response object.
    """
    ce_management_port = int(AVAILABLE_INPUTS.get("CE_MANAGEMENT_PORT", 8000))
    conn = None
    
    if protocol == "http" or protocol == "https":  # management server is always https.
        server_cert, server_key, client_ca = get_certs_locations()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(
            certfile=server_cert,
            keyfile=server_key,
        )
        if client_ca and os.path.exists(client_ca):
            context.load_verify_locations(cafile=client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False
        else:
            logger.warning("Common CA cert not found.")
        conn = http.client.HTTPSConnection(node_ip, ce_management_port, context=context)
    else:
        raise Exception("Invalid protocol")

    if handler.headers.get("Authorization"):
        new_token = create_token(handler.headers.get("Authorization"))
        if not new_token:
            logger.warning("Generated token is invalid, using the token from request.")
            headers = {
                "Authorization": handler.headers.get("Authorization"),
            }
        else:
            headers = {
                "Authorization": f"Bearer {new_token}",
            }
    else:
        headers = {}
    try:
        if payload:
            payload = json.dumps(payload)
        if params and isinstance(params, dict):
            endpoint += f"?{urlencode(params)}"

        conn.request(method=method, url=endpoint, headers=headers, body=payload)
        res = conn.getresponse()
        handle_http_errors(res=res)
        if should_stream:
            while True:
                response = res.readline().decode()
                if not response:
                    break
                yield response
        else:
            response = res.read().decode()
            try:
                response = json.loads(response)
            except (JSONDecodeError, TypeError) as e:
                logger.debug(
                    f"Error encountered while decoding response. Error: {e}.",
                    extra={"node": utils.NODE_IP},
                )
            yield response, res.code
    except ssl.CertificateError as e:
        enhanced_error = ssl.CertificateError(f"{e}. Please ensure configured CA key is same as Primary Node's CA key before executing CE Setup.")
        raise enhanced_error from e
    except Exception as e:
        raise e
    finally:
        if conn:
            conn.close()


@SimpleAPIServer.route("/unmount-volume", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def unmount_volume_route(handler):
    """
    Unmount glusterfs volume.

    Args:
        handler (Handler): The handler object.
        shared_directory_path (str): The path to the shared directory.

    Returns:
        A tuple containing the response body and HTTP status code.
        The response body is a string containing the command's output.

    Raises:
        HTTPException: If there is an error unmounting the volume.
    """
    try:
        content_length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(content_length).decode()
        data = json.loads(body)
    except (json.JSONDecodeError, AttributeError):
        write_chunk(handler.wfile, "End: Invalid Request.")
        end_stream(handler=handler, should_end_stream=True)
        return {"detail": "Invalid request"}, 400
    if data.get("shared_directory_path"):
        shared_directory_path = data.get("shared_directory_path")
    else:
        write_chunk(
            handler.wfile,
            "End: Please provide a valid shared directory path.\n",
        )
        end_stream(handler=handler, should_end_stream=True)
        return {"detail": "Please provide a valid shared directory path."}, 400

    if data.get("should_remove_brick_data"):
        should_remove_brick_data = True if data.get("should_remove_brick_data", "").lower() == "true" else False
    else:
        should_remove_brick_data = False

    return unmount_volume(
        handler=handler,
        shared_directory_path=shared_directory_path,
        should_end_stream=True,
        should_remove_brick_data=should_remove_brick_data,
    )


@SimpleAPIServer.route("/add-node", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def add_node(handler):
    """
    Add a new node to the cluster.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        node_ip (str): The IP address of the new node.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        HTTPException: If there is an error adding the node.
    """
    try:
        content_length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(content_length).decode()
        data = json.loads(body)
        node_ip = data.get("node_ip").strip()
    except (json.JSONDecodeError, AttributeError):
        write_chunk(handler.wfile, "End: Invalid Request.")
        end_stream(handler=handler, should_end_stream=True)
        return {"detail": "Invalid request"}, 400

    if not node_ip or (not isinstance(node_ip, str)):
        write_chunk(handler.wfile, "End: Node IP not provided.\n")
        end_stream(handler=handler)
        return {"detail": "Node IP not provided"}, 400
    elif not validate_network_address(node_ip):
        write_chunk(handler.wfile, "End: Invalid Node IP.\n")
        end_stream(handler=handler)
        return {"detail": "Invalid Node IP"}, 400

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        write_chunk(
            handler.wfile,
            f"End: Error loading environment variables. {str(error_msg)}\n",
        )
        end_stream(handler=handler)
        return {"details": error_msg}, 500

    # Node check management is up by making get call
    write_chunk(handler.wfile, "Info: Checking for Management server on new-node.\n")
    AVAILABLE_INPUTS["UI_PROTOCOL"] = (
        AVAILABLE_INPUTS.get("UI_PROTOCOL", "http").lower().strip()
    )
    try:
        response = check_management_server(
            node_ip=node_ip,
            handler=handler,
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            method="GET",
            endpoint="/api/management/node-details",
            should_stream=False,
        )
        response = response.__next__()
        if len(response) > 1 and response[1] != 200:
            if isinstance(response[0], dict):
                raise Exception(response[0].get("detail"))
            else:
                raise Exception(response[0])
        write_chunk(
            handler.wfile,
            f"Info: Connection to Management Server at {node_ip} established.\n",
            node_ip=node_ip,
        )
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"Error: Issue connecting to Management Server at {node_ip}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Issue connecting to Management Server at {node_ip}. {str(e)}"
        }, 400

    AVAILABLE_INPUTS["HA_ENABLED"] = True
    AVAILABLE_INPUTS["HA_CURRENT_NODE"] = node_ip
    AVAILABLE_INPUTS["HA_IP_LIST"] = update_ha_ip_list(
        AVAILABLE_INPUTS["HA_IP_LIST"], ip_to_add=node_ip
    )

    glusterfs_base_port = GLUSTERFS_BASE_PORT
    glusterfs_max_port = GLUSTERFS_MAX_PORT
    try:
        response = check_management_server(
            node_ip=node_ip,
            handler=handler,
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            method="GET",
            endpoint="/api/management/get-config",
            should_stream=False,
        )
        response = response.__next__()
        if len(response) > 1 and response[1] != 200:
            if isinstance(response[0], dict):
                raise Exception(response[0].get("detail"))
            else:
                raise Exception(response[0])
        if isinstance(response[0], dict):
            try:
                glusterfs_base_port = int(response[0].get("GLUSTERFS_BASE_PORT", GLUSTERFS_BASE_PORT))
                glusterfs_max_port = int(response[0].get("GLUSTERFS_MAX_PORT", GLUSTERFS_MAX_PORT))
            except Exception:
                glusterfs_base_port = GLUSTERFS_BASE_PORT
                glusterfs_max_port = GLUSTERFS_MAX_PORT
    except Exception as e:
        write_chunk(
            handler.wfile,
            (
                f"Warning: Error encountered while reading config file from {CONFIG_FILE_PATH}. Error: {str(e)}, "
                "continuing with default values for GlusterFS Ports\n"
            ),
        )

    # Update the config file.
    data = {
        "HA_ENABLED": AVAILABLE_INPUTS["HA_ENABLED"],
        "HA_CURRENT_NODE": AVAILABLE_INPUTS["HA_CURRENT_NODE"],
        "HA_NFS_DATA_DIRECTORY": f"{AVAILABLE_INPUTS.get('HA_NFS_DATA_DIRECTORY')}",
        "HA_IP_LIST": AVAILABLE_INPUTS.get("HA_IP_LIST", ""),
        "GLUSTERFS_BASE_PORT": glusterfs_base_port,
        "GLUSTERFS_MAX_PORT": glusterfs_max_port,
    }
    try:
        write_chunk(handler.wfile, "Info: Updating the Cloud Exchange config file.\n")
        response = check_management_server(
            handler=handler,
            endpoint="/api/management/update-config",
            node_ip=node_ip,
            method="POST",
            payload=data,
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=False,
        )
        response = response.__next__()
        if len(response) > 1 and response[1] != 200:
            if isinstance(response[0], dict):
                raise Exception(response[0].get("detail"))
            else:
                raise Exception(response[0])
        write_chunk(handler.wfile, "Info: Config file updated.\n", node_ip=node_ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while updating the Cloud Exchange config file on new node. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while updating the Cloud Exchange config file on new node. {str(e)}"
        }, 500

    # Validating prerequisites are met
    try:
        write_chunk(handler.wfile, "Info: Validating prerequisites for new node.\n")
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/setup",
            node_ip=node_ip,
            method="GET",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            params={"flags": "--check-prerequisites HA"},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=node_ip)
        write_chunk(handler.wfile, "Info: Prerequisites validated for new node.\n")
    except Exception as e:
        write_chunk(
            handler.wfile,
            (
                f"Error: Error encountered while validating prerequisites reverting the Cloud Exchange config file "
                f"changes. Error: {str(e)}\n"
            ),
        )
        # Revert to default config data
        data = {
            "HA_ENABLED": "",
            "HA_CURRENT_NODE": "",
            "HA_NFS_DATA_DIRECTORY": "",
            "HA_IP_LIST": "",
            "GLUSTERFS_BASE_PORT": "",
            "GLUSTERFS_MAX_PORT": "",
        }
        AVAILABLE_INPUTS["HA_IP_LIST"] = update_ha_ip_list(AVAILABLE_INPUTS["HA_IP_LIST"], ip_to_remove=node_ip)
        try:
            write_chunk(
                handler.wfile,
                "Info: Reverting to default Cloud Exchange config data.\n",
            )
            response = check_management_server(
                handler=handler,
                endpoint="/api/management/update-config",
                node_ip=node_ip,
                method="POST",
                payload=data,
                protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
                should_stream=False,
            )
            response = response.__next__()
            if len(response) > 1 and response[1] != 200:
                if isinstance(response[0], dict):
                    raise Exception(response[0].get("detail"))
                else:
                    raise Exception(response[0])
            write_chunk(
                handler.wfile,
                "Info: Cloud Exchange config file reverted to default data.\n",
                node_ip=node_ip,
            )
        except Exception as e:
            write_chunk(
                handler.wfile,
                (
                    f"Error: Error encountered while reverting to default Cloud Exchange config data on new node. "
                    f"Error: {str(e)}\n"
                ),
            )

        write_chunk(
            handler.wfile,
            (
                f"End: Error encountered while validating prerequisites for new node. "
                f"Error: {str(e)}\n"
            ),
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while validating prerequisites for new node. {str(e)}"
        }, 500

    # install GlusterFS on new node
    shared_base_directory_path = "/".join(
        (AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY").strip().rstrip("/").split("/"))[
            :-1
        ]
    )  # parent dir of NFS_directory # /opt/shared/
    data = {
        "shared_directory_path": shared_base_directory_path,
        "glusterfs_base_port": glusterfs_base_port,
        "glusterfs_max_port": glusterfs_max_port,
    }
    try:
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/install-gluster",
            node_ip=node_ip,
            method="POST",
            payload=data,
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
        ):
            if response_chunk[:3].upper() == "END":  # any better? jsonl??
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=node_ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while installing GlusterFS on new node. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while installing GlusterFS on new node. {str(e)}"
        }, 500

    # peer probe from current
    write_chunk(handler.wfile, "Info: Peering with new node.\n")
    command = f"{SUDO_PREFIX} gluster peer probe {node_ip}"
    command = command.strip().split(" ")
    response = execute_command_with_logging(
        command, handler, message="peering with new node"
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return {"detail": "Error encountered while peering with new node."}, 500
    write_chunk(handler.wfile, "Info: Successfully peered with new node.\n")

    logger.info("sleeping for 5 seconds", extra={"node": utils.NODE_IP})
    time.sleep(5)  # wait for 5 seconds to have the node accepted as peer.

    brick_exists = False
    search_string = f"{node_ip}:{shared_base_directory_path}/gluster/bricks/1/brick"
    # check if brick is already added.
    command = f"{SUDO_PREFIX} gluster volume info CloudExchange | grep {search_string}".strip()
    try:
        for message in execute_command(command, shell=True):
            message_str = message.get("message", "\n")
            type_str = message.get("type", "")
            if type_str == "stderr":
                write_chunk(handler.wfile, f"Error: {message_str}")
            elif type_str == "returncode" and message.get("code", 0) != 0:
                brick_exists = False
            else:
                if search_string in message_str:
                    write_chunk(
                        handler.wfile,
                        f"Info: Brick already exists at {search_string}.\n",
                    )
                    brick_exists = True
                    break
    except GeneratorExit:
        pass
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while checking for existing bricks. Error: {str(e)}\n.",
        )
        end_stream(handler=handler)

    if not brick_exists:
        write_chunk(handler.wfile, "Info: Adding new brick to CloudExchange volume.\n")
        # Add new brick to current GlusterFS volume.
        new_replica_count = len(AVAILABLE_INPUTS.get("HA_IP_LIST", "").split(","))
        command = (
            f"{SUDO_PREFIX} gluster volume add-brick CloudExchange replica {new_replica_count} "
            f"{node_ip}:{shared_base_directory_path}/gluster/bricks/1/brick force"
        )
        command = command.strip().split(" ")
        try:
            for message in retirable_execute_command(
                command, input_data="y\n", max_retries=3, max_delay=5
            ):
                message_str = message.get("message", "\n")
                type_str = message.get("type", "")
                if type_str == "stderr":
                    write_chunk(handler.wfile, f"Error: {message_str}")
                elif type_str == "returncode" and message.get("code", 0) != 0:
                    write_chunk(
                        handler.wfile,
                        (
                            "End: Could not add new brick to CloudExchange Volume. "
                            f"Command failed with return code: {str(message.get('code', 0))}.\n"
                        ),
                    )
                    return {
                        "detail": (
                            "Could not add new brick to CloudExchange Volume. "
                            f"Command failed with return code: {str(message.get('code', 0))}"
                        )
                    }, 500
                elif type_str == "retry":
                    write_chunk(handler.wfile, f"Info: {message_str}\n")
                else:
                    write_chunk(handler.wfile, f"Info: {message_str}")
        except Exception as e:
            write_chunk(
                handler.wfile,
                f"End: Error encountered while adding new brick to CloudExchange volume. Error: {str(e)}\n",
            )
            end_stream(handler=handler)
            return {
                "detail": "Error encountered while adding new brick to CloudExchange volume."
            }, 500
    try:
        write_chunk(
            handler.wfile, "Info: Triggering full heal on CloudExchange volume.\n"
        )
        command = f"{SUDO_PREFIX} gluster volume heal CloudExchange full"
        command = command.strip().split(" ")
        for message in retirable_execute_command(command, max_retries=3, max_delay=5):
            message_str = message.get("message", "\n")
            type_str = message.get("type", "")
            if type_str == "stderr":
                write_chunk(handler.wfile, f"Error: {message_str}")
            elif type_str == "returncode" and message.get("code", 0) != 0:
                write_chunk(
                    handler.wfile,
                    "End: Heal operation failed on the volume CloudExchange. "
                    f"Command failed with return code: {str(message.get('code', 0))}.\n",
                )
                return {
                    "detail": (
                        "Heal operation failed on the volume CloudExchange. "
                        f"Command failed with return code: {str(message.get('code', 0))}"
                    )
                }, 500
            elif type_str == "retry":
                write_chunk(handler.wfile, f"Info: {message_str}\n")
            else:
                write_chunk(handler.wfile, f"Info: {message_str}")
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while triggering heal operation on CloudExchange volume. Error: {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": "Error encountered while triggering heal operation on CloudExchange volume."
        }, 500

    # Mount GlusterFS volume on new node
    data = {
        "shared_directory_path": shared_base_directory_path,
        "current_node_ip": node_ip,
    }
    try:
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/ensure-volume",
            node_ip=node_ip,
            method="POST",
            payload=data,
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=node_ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while mounting GlusterFS volume on new node. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while mounting GlusterFS volume on new node. {str(e)}"
        }, 500

    # Run setup with HA values updated on new node.
    try:
        write_chunk(handler.wfile, "Info: Setting up new node for HA.\n")
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/setup",
            node_ip=node_ip,
            method="GET",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            params={"flags": "--avoid-service-restart"},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=node_ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while running setup on new node. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while running setup on new node. {str(e)}"
        }, 500

    write_chunk(handler.wfile, "Info: Restarting other nodes in cluster now...\n")
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        write_chunk(handler.wfile, "End: Error loading environment variables.\n")
        end_stream(handler=handler)
        return {"details": error_msg}, 500

    if (
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
        and isinstance(AVAILABLE_INPUTS.get("HA_CURRENT_NODE"), str)
        and len(AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()) > 0
        and utils.NODE_IP != AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()
    ):
        utils.NODE_IP = AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()

    primary_node = AVAILABLE_INPUTS["HA_PRIMARY_NODE_IP"].strip()
    # Restart other nodes to update certs and env
    for ip in AVAILABLE_INPUTS["HA_IP_LIST"].split(","):
        ip = ip.strip()
        if (ip == node_ip) or (ip == primary_node):
            continue
        write_chunk(handler.wfile, f"Info: Stopping Cloud Exchange on Node {ip}.\n")
        try:
            for response_chunk in check_management_server(
                handler=handler,
                endpoint="/api/management/stop-ce",
                node_ip=ip,
                method="POST",
                protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
                should_stream=True,
                payload={"node_ip": ip},
            ):
                if response_chunk[:3].upper() == "END":
                    raise Exception(response_chunk)
                else:
                    write_chunk(handler.wfile, response_chunk, node_ip=ip)
        except Exception as e:
            write_chunk(
                handler.wfile,
                f"End: Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}\n",
            )
            end_stream(handler=handler)
            return {
                "detail": f"Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}"
            }, 500

    write_chunk(
        handler.wfile, f"Info: Stopping Cloud Exchange Primary Node {primary_node}.\n"
    )
    try:
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/stop-ce",
            node_ip=primary_node,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            payload={"node_ip": primary_node},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=primary_node)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while stopping Cloud Exchange on Node {primary_node}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while stopping Cloud Exchange on Node {primary_node}. {str(e)}"
        }, 500

    #  Restart primary node to update certs and env
    write_chunk(
        handler.wfile,
        f"Info: Starting Cloud Exchange on primary node {primary_node}.\n",
    )
    try:
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/start-ce",
            node_ip=primary_node,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            payload={"node_ip": primary_node},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=primary_node)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while starting Cloud Exchange on Node {primary_node}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while starting Cloud Exchange on Node {primary_node}. {str(e)}"
        }, 500

    # Restart other nodes to update certs and env
    write_chunk(handler.wfile, "Info: Starting other nodes in cluster now...\n")
    try:
        for ip in AVAILABLE_INPUTS["HA_IP_LIST"].split(","):
            ip = ip.strip()
            if (ip == node_ip) or (ip == primary_node):
                continue
            write_chunk(handler.wfile, f"Info: Starting Cloud Exchange on Node {ip}.\n")
            for response_chunk in check_management_server(
                handler=handler,
                endpoint="/api/management/start-ce",
                node_ip=ip,
                method="POST",
                protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
                should_stream=True,
                payload={"node_ip": ip},
            ):
                if response_chunk[:3].upper() == "END":
                    raise Exception(response_chunk)
                else:
                    write_chunk(handler.wfile, response_chunk, node_ip=ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}"
        }, 500

    try:
        # run start on new node.
        write_chunk(handler.wfile, "Info: Starting new node in cluster now...\n")
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/start-ce",
            node_ip=node_ip,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            payload={"node_ip": node_ip},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=node_ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while running start on new node. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while running start on new node. {str(e)}"
        }, 500

    write_chunk(
        handler.wfile,
        "Info: You can now access new cluster node here: " + node_ip + "\n",
    )

    end_stream(handler=handler)
    logger.info("Node added successfully to HA Cluster", extra={"node": utils.NODE_IP})
    return {"detail": "Node added successfully"}, 200


def restart_nodes(handler, ip):
    """Restart the Cloud Exchange on a node.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.
        ip (str): The IP of the node to be restarted.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        HTTPException: If there is an error restarting the node.
    """
    write_chunk(handler.wfile, f"Info: Restarting Cloud Exchange on Node {ip}.\n")
    try:
        # run start on new node.
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/stop-ce",
            node_ip=ip,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            payload={"node_ip": ip},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=ip)

        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/start-ce",
            node_ip=ip,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            payload={"node_ip": ip},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while running restarting Cloud Exchange on node: {ip}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while running restarting Cloud Exchange on node: {ip}. {str(e)}"
        }, 500

    return {"detail": "Cloud Exchange restarted"}, 200


def get_ip_list(env_value):
    """Return a list of IP addresses from an environment variable.

    Args:
        env_value (str): The environment variable value.

    Returns:
        List[str]: A list of IP addresses.
    """
    return [ip.strip() for ip in env_value.split(",") if ip.strip()]


def update_ha_ip_list(env_value, ip_to_add=None, ip_to_remove=None):
    """Update a list of IP addresses from an environment variable.

    Args:
        env_value (str): The environment variable value.

    Returns:
        List[str]: A list of IP addresses.
    """
    ip_list = get_ip_list(env_value)

    if ip_to_add:
        if ip_to_add not in ip_list:
            ip_list.append(ip_to_add)

    if ip_to_remove:
        ip_list = [ip for ip in ip_list if ip != ip_to_remove]

    return ",".join(ip_list)


@SimpleAPIServer.route("/remove-node", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def remove_node(handler):
    """
    Remove a node from the HA Cluster.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        HTTPException: If there is an error removing the node.
    """
    try:
        content_length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(content_length).decode()
        data = json.loads(body)
        node_ip = data.get("node_ip").strip()
    except (json.JSONDecodeError, AttributeError):
        write_chunk(handler.wfile, "End: Invalid Request.")
        end_stream(handler=handler)
        return {"detail": "Invalid request"}, 400

    if not node_ip or (not isinstance(node_ip, str)):
        write_chunk(handler.wfile, "Error: Node IP not provided.\n")
        end_stream(handler=handler)
        return {"detail": "Node IP not provided"}, 400
    elif not validate_network_address(node_ip):
        write_chunk(handler.wfile, "End: Invalid Node IP.\n")
        end_stream(handler=handler)
        return {"detail": "Invalid Node IP"}, 400

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        write_chunk(handler.wfile, "End: Error loading environment variables.\n")
        end_stream(handler=handler)
        return {"details": error_msg}, 500

    # node check management is up by making get call
    write_chunk(handler.wfile, "Info: Checking for Management server on node.\n")
    AVAILABLE_INPUTS["UI_PROTOCOL"] = (
        AVAILABLE_INPUTS.get("UI_PROTOCOL", "http").lower().strip()
    )
    try:
        response = check_management_server(
            node_ip=node_ip,
            handler=handler,
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            method="GET",
            endpoint="/api/management/node-details",
            should_stream=False,
        )
        response = response.__next__()
        if len(response) > 1 and response[1] != 200:
            if isinstance(response[0], dict):
                raise Exception(response[0].get("detail"))
            else:
                raise Exception(response[0])
        write_chunk(
            handler.wfile,
            "Info: Connection to Management Server established.\n",
            node_ip=node_ip,
        )
    except Exception as e:
        write_chunk(
            handler.wfile, f"Error: Issue connecting to Management Server. {str(e)}\n"
        )
        end_stream(handler=handler)
        return {
            "detail": f"Issue connecting to Management Server on node {node_ip}. {str(e)}"
        }, 400

    # stop
    try:
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/stop-ce",
            node_ip=node_ip,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            payload={"node_ip": node_ip},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=node_ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while stopping Cloud Exchange on node: {node_ip}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while stopping Cloud Exchange on node: {node_ip}. {str(e)}"
        }, 500

    # update_config
    AVAILABLE_INPUTS["HA_IP_LIST"] = update_ha_ip_list(
        AVAILABLE_INPUTS.get("HA_IP_LIST", ""), ip_to_remove=node_ip
    )
    try:
        data = {"HA_IP_LIST": AVAILABLE_INPUTS["HA_IP_LIST"]}
        response = check_management_server(
            handler=handler,
            endpoint="/api/management/update-env",
            node_ip=node_ip,
            method="PUT",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            payload=data,
        )
        response = response.__next__()
        if len(response) > 1 and response[1] != 200:
            if isinstance(response[0], dict):
                raise Exception(response[0].get("detail"))
            else:
                raise Exception(response[0])
        write_chunk(handler.wfile, "Info: Env file updated.\n", node_ip=node_ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while updating env file on node {node_ip}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while updating env file on node {node_ip}. {str(e)}"
        }, 500

    # remove brick from GlusterFS volume
    write_chunk(handler.wfile, "Info: Removing brick from GlusterFS volume.\n")
    replica_nodes = len(AVAILABLE_INPUTS.get("HA_IP_LIST", "").rstrip(",").split(","))
    shared_dir_base_path = "/".join(
        (AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY").strip().rstrip("/").split("/"))[
            :-1
        ]
    )
    command = (
        f"{SUDO_PREFIX} gluster volume remove-brick CloudExchange replica "
        f"{replica_nodes} {node_ip}:{shared_dir_base_path}/gluster/bricks/1/brick force"
    )
    command = command.strip().split(" ")
    response = execute_command_with_logging(
        command,
        handler,
        input_data="y\n",
        message="removing brick from GlusterFS volume",
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return {
            "detail": "Error encountered while removing brick from GlusterFS volume."
        }, 500
    write_chunk(
        handler.wfile, "Info: Successfully removed brick from GlusterFS volume.\n"
    )

    # Unmount.
    try:
        data = {
            "shared_directory_path": shared_dir_base_path,
            "should_remove_brick_data": "true",
        }
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/unmount-volume",
            node_ip=node_ip,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            payload=data,
            should_stream=True,
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=node_ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while un-mounting CloudExchange volume on node: {node_ip}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while un-mounting CloudExchange volume on node: {node_ip}. {str(e)}"
        }, 500

    # detach-node
    write_chunk(handler.wfile, f"Info: Detaching node {node_ip} from GlusterFS.\n")
    command = f"{SUDO_PREFIX} gluster peer detach {node_ip}"
    command = command.strip().split(" ")
    response = execute_command_with_logging(
        command, handler, input_data="y\n", message="detaching node from GlusterFS"
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return {"detail": "Error encountered while detaching node from GlusterFS."}, 500
    write_chunk(handler.wfile, "Info: Successfully detached node from GlusterFS.\n")

    write_chunk(handler.wfile, f"Info: Removed node: {node_ip} from HA Cluster.\n")

    # Update the HA_IP_LIST and HA_PRIMARY_NODE_IP
    write_chunk(handler.wfile, "Info: Fetching updated environment variables.\n")
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        write_chunk(
            handler.wfile,
            f"End: Error loading environment variables. {str(error_msg)}\n",
        )
        end_stream(handler=handler)
        return {"details": error_msg}, 500

    if (
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
        and isinstance(AVAILABLE_INPUTS.get("HA_CURRENT_NODE"), str)
        and len(AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()) > 0
        and utils.NODE_IP != AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()
    ):
        utils.NODE_IP = AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()

    primary_node = AVAILABLE_INPUTS["HA_PRIMARY_NODE_IP"].strip()
    # Restart other nodes to update certs and env
    for ip in AVAILABLE_INPUTS["HA_IP_LIST"].split(","):
        ip = ip.strip()
        if (ip == node_ip) or (ip == primary_node):
            continue
        write_chunk(handler.wfile, f"Info: Stopping Cloud Exchange on Node {ip}.\n")
        try:
            for response_chunk in check_management_server(
                handler=handler,
                endpoint="/api/management/stop-ce",
                node_ip=ip,
                method="POST",
                protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
                should_stream=True,
                payload={"node_ip": ip},
            ):
                if response_chunk[:3].upper() == "END":
                    raise Exception(response_chunk)
                else:
                    write_chunk(handler.wfile, response_chunk, node_ip=ip)
        except Exception as e:
            write_chunk(
                handler.wfile,
                f"End: Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}\n",
            )
            end_stream(handler=handler)
            return {
                "detail": f"Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}"
            }, 500

    write_chunk(
        handler.wfile, f"Info: Stopping Cloud Exchange Primary Node {primary_node}.\n"
    )
    try:
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/stop-ce",
            node_ip=primary_node,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            payload={"node_ip": primary_node},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=primary_node)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while stopping Cloud Exchange on Node {primary_node}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while stopping Cloud Exchange on Node {primary_node}. {str(e)}"
        }, 500

    # Restart other nodes to update certs and env
    write_chunk(
        handler.wfile,
        f"Info: Starting Cloud Exchange on Primary Node {primary_node}.\n",
    )
    try:
        for response_chunk in check_management_server(
            handler=handler,
            endpoint="/api/management/start-ce",
            node_ip=primary_node,
            method="POST",
            protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
            should_stream=True,
            payload={"node_ip": primary_node},
        ):
            if response_chunk[:3].upper() == "END":
                raise Exception(response_chunk)
            else:
                write_chunk(handler.wfile, response_chunk, node_ip=primary_node)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while starting Cloud Exchange on Node {primary_node}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while starting Cloud Exchange on Node {primary_node}. {str(e)}"
        }, 500

    write_chunk(handler.wfile, "Info: Starting other nodes in cluster now...\n")
    try:
        for ip in AVAILABLE_INPUTS["HA_IP_LIST"].split(","):
            ip = ip.strip()
            if (ip == node_ip) or (ip == primary_node):
                continue
            write_chunk(handler.wfile, f"Info: Starting Cloud Exchange on Node {ip}.\n")
            for response_chunk in check_management_server(
                handler=handler,
                endpoint="/api/management/start-ce",
                node_ip=ip,
                method="POST",
                protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
                should_stream=True,
                payload={"node_ip": ip},
            ):
                if response_chunk[:3].upper() == "END":
                    raise Exception(response_chunk)
                else:
                    write_chunk(handler.wfile, response_chunk, node_ip=ip)
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}\n",
        )
        end_stream(handler=handler)
        return {
            "detail": f"Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}"
        }, 500

    write_chunk(handler.wfile, f"End: Removed node: {node_ip} from HA Cluster.\n")
    end_stream(handler=handler)
    return {"detail": f"Removed node: {node_ip} from HA Cluster."}, 200


@SimpleAPIServer.route("/disable-ha", stream=True, methods=["POST"], scopes=[ADMIN_ROLE])
def disable_ha(handler):
    """
    Disable HA.

    Args:
        handler (wsgiref.handlers.HTTPResponse): The wsgi response handler.

    Returns:
        Tuple[Dict[str, Any], int]: A response dictionary and a status code.
            The response dictionary will contain a "detail" key with a message.

    Raises:
        HTTPException: If there is an error disabling HA.
    """
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        write_chunk(
            handler.wfile,
            f"End: Error loading environment variables. {str(error_msg)}\n",
        )
        end_stream(handler=handler)
        return {"details": error_msg}, 500

    if (
        AVAILABLE_INPUTS.get("HA_IP_LIST")
        and len(AVAILABLE_INPUTS.get("HA_IP_LIST").strip().rstrip(",").split(",")) > 1
    ):
        write_chunk(
            handler.wfile,
            "End: Can not disable ha, there are more than one node available in cluster."
            " Please remove the secondary nodes from the cluster.\n",
        )
        end_stream(handler=handler)
        return {
            "details": (
                "Can not disable ha, there are more than one node available in cluster."
                " Please remove the secondary nodes from the cluster."
            )
        }, 400

    shared_base_directory = "/".join(
        (AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY").strip().rstrip("/").split("/"))[
            :-1
        ]
    )
    # Copy custom plugins from shared directory to "data" folder as in HA
    # if anyone using custom plugins they will be on shared directory
    command = (
        f"{SUDO_PREFIX} cp -r {shared_base_directory}/data/custom_plugins {shared_base_directory}/data/plugins "
        f"{shared_base_directory}/data/repos ./data/"
    )
    command = command.strip().split(" ")
    write_chunk(
        handler.wfile,
        "Info: Copying plugins, repos and custom plugins to data directory.\n",
    )
    response = execute_command_with_logging(
        command,
        handler,
        message="copying plugins, repos and custom plugins to data directory",
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return {
            "detail": "Error encountered while copying plugins, repos and custom plugins to data directory."
        }, 500

    # Move the custom certs to data directory.
    write_chunk(handler.wfile, "Info: Moving custom certs and ssl certs to data directory.\n")
    command = f"{SUDO_PREFIX} cp -r {shared_base_directory}/data/config/ca_certs {shared_base_directory}/data/config/ssl_certs ./data/"
    command = command.strip().split(" ")
    response = execute_command_with_logging(
        command, handler, message="moving custom certs and ssl certs to data directory"
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response
    write_chunk(handler.wfile, "Info: Moved custom certs and ssl certs.\n")

    # Stop CE
    write_chunk(handler.wfile, "Info: Stopping Cloud Exchange\n")
    response = stop_ce(handler=handler, should_end_stream=False, as_api=False)
    if response[1] != 200:
        end_stream(handler=handler)
        return response
    write_chunk(handler.wfile, "Info: Stopped Cloud Exchange\n")

    # Copy env files from shared directory to "data" folder as in HA
    # if anyone using custom plugins they will be on shared directory
    command = f"{SUDO_PREFIX} cp -r {shared_base_directory}/data/config/.env* ./".strip()
    response = execute_command_with_logging(
        command, handler, shell=True, message="copying env files from shared directory"
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return {
            "detail": "Error encountered while copying env files from shared directory."
        }, 500
    write_chunk(handler.wfile, "Info: Copied env files from shared directory.\n")

    # Update Cloud Exchange config.
    try:
        write_chunk(handler.wfile, "Info: Updating Cloud Exchange env file.\n")
        data = {
            "HA_ENABLED": False,
            "HA_IP_LIST": "",
            "HA_CURRENT_NODE": "",
            "HA_NFS_DATA_DIRECTORY": "",
            "JWT_SECRET": AVAILABLE_INPUTS["JWT_SECRET"],
            "HA_PRIMARY_NODE_IP": "",
        }
        response = update_env(handler=handler, update_data=data, env_file=".env")
        if response[1] != 200:
            end_stream(handler=handler)
            return response
        write_chunk(handler.wfile, "Info: Cloud Exchange env file updated.\n")

        # update_config
        write_chunk(handler.wfile, "Info: Updating Cloud Exchange config file.\n")
        response = update_config_file(handler=handler, keys_to_update=data)
        if response[1] != 200:
            end_stream(handler=handler)
            return response
        write_chunk(handler.wfile, "Info: Cloud Exchange config file updated.\n")
    except Exception as e:
        write_chunk(
            handler.wfile,
            f"End: Error encountered while updating Cloud Exchange config. Error: {str(e)} \n",
        )
        end_stream(handler=handler)
        return {
            "detail": "Error encountered while updating Cloud Exchange config."
        }, 500

    write_chunk(
        handler.wfile, "Info: Setting up Cloud Exchange as Standalone deployment."
    )
    response = setup(
        handler=handler,
        should_end_stream=False,
        flags="--avoid-service-restart",
        is_api=False,
    )
    if response[1] != 200:
        end_stream(handler)
        return response

    response = stop_delete_gluster_volume(handler=handler)
    if response[1] != 200:
        end_stream(handler=handler)
        return response
    response = unmount_volume(
        handler=handler,
        shared_directory_path=shared_base_directory,
        should_remove_brick_data=True,
        should_end_stream=False,
    )
    if response[1] != 200:
        end_stream(handler=handler)
        return response

    write_chunk(handler.wfile, "Info: Starting Standalone Cloud Exchange deployment.")
    response = start_ce(handler=handler, should_end_stream=False, as_api=False)
    if response[1] != 200:
        end_stream(handler=handler)
        return response

    write_chunk(handler.wfile, "Info: Cloud Exchange started successfully.\n")
    end_stream(handler=handler)
    return {"detail": "Cloud Exchange started."}, 200


@SimpleAPIServer.route("/system-stats", methods=["GET"], require_auth=False, scopes=[])
def system_stats(handler):
    """
    Endpoint to retrieve system statistics for the current node and optionally across the cluster.

    This function collects CPU, memory, and disk usage statistics for the current node.
    If cluster statistics are requested (default), it also collects stats from other nodes in the HA cluster.

    Args:
        handler: Request handler object containing the request details

    Query Parameters:
        skip_cluster (bool, optional): If true, only returns stats for the current node.
            Defaults to False.

    Returns:
        tuple: A tuple containing:
            - dict: System statistics in the following format:
                {
                    "node_ip": {
                        "cpu": {
                            "processors": int,
                            "load_avg_1min_percentage": float,
                            "load_avg_5min_percentage": float,
                            "load_avg_15min_percentage": float
                        },
                        "memory": {
                            "total_GB": float,
                            "used_GB": float,
                            "percent": float
                        },
                        "disk": {
                            "total_GB": float,
                            "used_GB": float,
                            "available_GB": float,
                            "percent_used": float
                        }
                    }
                }
            - int: HTTP status code (200 for success)

    Raises:
        Exception: If there's an error retrieving stats from other nodes in the cluster
    """
    skip_cluster = False
    try:
        parsed_url = urlparse(handler.path)
        query_params = parse_qs(parsed_url.query)
        skip_cluster = (
            True
            if query_params.get("skip_cluster", [""])[0].lower() == "true"
            else False
        )
    except Exception:
        skip_cluster = False

    cpu = get_cpu_count()
    load = get_load_average(cpu)
    mem = get_memory_usage()
    disk = get_disk_usage()

    node_response = {"cpu": {**load, "processors": cpu}, "memory": mem, "disk": disk}
    if skip_cluster:
        return node_response, 200

    response = get_node_ip()  # updates the utils.NODE_IP to node ip.
    if response[1] != 200:
        return response

    if (
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
        and isinstance(AVAILABLE_INPUTS.get("HA_CURRENT_NODE"), str)
        and len(AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()) > 0
        and utils.NODE_IP != AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()
    ):
        utils.NODE_IP = AVAILABLE_INPUTS.get("HA_CURRENT_NODE").strip()

    ha_stats = {utils.NODE_IP: node_response}
    ha_ip_list = AVAILABLE_INPUTS.get("HA_IP_LIST", None)

    if not ha_ip_list:
        return ha_stats, 200

    for ip in ha_ip_list.split(","):
        if ip == "" or ip == utils.NODE_IP:
            continue
        logger.info(f"triggering the api call for {ip}", extra={"node": utils.NODE_IP})
        response = check_management_server(
            node_ip=ip,
            handler=handler,
            method="GET",
            endpoint="/api/management/system-stats",
            should_stream=False,
            params={"skip_cluster": True},
        )
        response = response.__next__()
        if len(response) > 1 and response[1] != 200:
            if isinstance(response[0], dict):
                raise Exception(response[0].get("detail"))
            else:
                raise Exception(response[0])
        elif len(response) > 1 and response[1] == 200:
            ha_stats[ip] = response[0]

    return ha_stats, 200


if __name__ == "__main__":
    configs = read_config_file(CONFIG_FILE_PATH)
    set_sudo_prefix()
    configure_logger(
        log_file_max_bytes=configs.get("LOG_FILE_MAX_BYTES", (10 * 1024 * 1024)),
        backup_count=configs.get("LOG_FILE_BACKUP_COUNT", 5),
        log_file_name=LOG_FILE_NAME,
        logs_directory=LOGS_DIRECTORY,
    )
    get_node_ip()
    run(server_class=ThreadingHTTPServer)
