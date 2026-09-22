#!/usr/bin/env python3
"""Management server for the Netskope Cloud Exchange."""

import re
import base64
import shlex
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
import shutil
import subprocess
import ssl
import zipfile
import uuid
import threading
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
    fetch_container_info,
)

SECRET_KEY = os.getenv("JWT_SECRET")
ACCESS_TOKEN_EXPIRE_MINUTES = 60
API_PREFIX = "/api/management"
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
JWT_ALGORITH_LIB_MAP = {"HS256": hashlib.sha256}
DEFAULT_USER = "management"
DIAGNOSE_OUTPUT_DIR_DEFAULT = "./data/diagnose_output"
CURRENT_DIAGNOSE_JOB = None
TLSV2_CIPHER_STRING = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"
    ":ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
)
_diagnose_job_lock = threading.Lock()


def _get_diagnose_output_dir():
    """
    Get the diagnose output directory based on HA mode.

    In HA mode, uses the shared NFS directory for cross-node access.
    In standalone mode, uses the local default directory.

    Returns:
        str: Path to the diagnose output directory
    """
    shared_dir_base_path = "/".join(
        (AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY", "").strip().rstrip("/").split("/"))[:-1]
    )

    if shared_dir_base_path:
        diagnose_output_dir = os.path.join(shared_dir_base_path, "data", "diagnose_output")
    else:
        diagnose_output_dir = DIAGNOSE_OUTPUT_DIR_DEFAULT
    logger.debug(f"Diagnose Directory : {diagnose_output_dir}")
    return diagnose_output_dir


def _get_diagnose_job_metadata_path(job_id, output_dir=None):
    """
    Get the path to the job metadata file for a given job_id.

    Args:
        job_id: The diagnose job ID
        output_dir: Optional output directory, defaults to _get_diagnose_output_dir()

    Returns:
        str: Path to the metadata JSON file
    """
    if output_dir is None:
        output_dir = _get_diagnose_output_dir()
    return os.path.join(output_dir, f".diagnose_job_{job_id}.json")


def _save_diagnose_job_metadata(job_data, output_dir=None):
    """
    Save diagnose job metadata to a file for persistence across restarts.

    Args:
        job_data: Dictionary containing job state
        output_dir: Optional output directory
    """
    if not job_data or not job_data.get("job_id"):
        logger.warning("Cannot save metadata: job_data is empty or missing job_id", extra={"node": utils.NODE_IP})
        return

    try:
        if output_dir is None:
            output_dir = _get_diagnose_output_dir()
        os.makedirs(output_dir, exist_ok=True)

        metadata_path = _get_diagnose_job_metadata_path(job_data["job_id"], output_dir)
        logger.info(f"Attempting to save metadata to: {metadata_path}", extra={"node": utils.NODE_IP})
        with open(metadata_path, "w") as f:
            json.dump(job_data, f, indent=2)
        logger.info(f"Successfully saved diagnose job metadata: {metadata_path}", extra={"node": utils.NODE_IP})
    except Exception as e:
        logger.error(f"Failed to save diagnose job metadata to {metadata_path}: {e}", extra={"node": utils.NODE_IP})
        raise e


def _load_diagnose_job_metadata(job_id, output_dir=None):
    """
    Load diagnose job metadata from file.

    Args:
        job_id: The diagnose job ID to load
        output_dir: Optional output directory

    Returns:
        dict or None: Job metadata if found and valid, None otherwise
    """
    try:
        if output_dir is None:
            output_dir = _get_diagnose_output_dir()

        metadata_path = _get_diagnose_job_metadata_path(job_id, output_dir)
        if not os.path.exists(metadata_path):
            return None

        with open(metadata_path, "r") as f:
            job_data = json.load(f)

        # Validate the loaded data has required fields
        if job_data.get("job_id") == job_id:
            return job_data
        return None
    except Exception as e:
        logger.warning(f"Failed to load diagnose job metadata for {job_id}: {e}", extra={"node": utils.NODE_IP})
        return None


def _delete_diagnose_job_metadata(job_id, output_dir=None):
    """
    Delete diagnose job metadata file.

    Args:
        job_id: The diagnose job ID
        output_dir: Optional output directory
    """
    try:
        if output_dir is None:
            output_dir = _get_diagnose_output_dir()

        metadata_path = _get_diagnose_job_metadata_path(job_id, output_dir)
        if os.path.exists(metadata_path):
            os.remove(metadata_path)
            logger.info(f"Deleted diagnose job metadata: {metadata_path}", extra={"node": utils.NODE_IP})
    except Exception as e:
        logger.warning(f"Failed to delete diagnose job metadata: {e}", extra={"node": utils.NODE_IP})


def _cleanup_all_diagnose_files(output_dir=None, exclude_job_id=None):
    """
    Clean up all diagnose job files (metadata and zip files) in the output directory.

    Ensures only one diagnose job's files exist at a time. Called when starting a new job.

    Args:
        output_dir: Optional output directory
        exclude_job_id: Optional job_id to exclude from cleanup (keep this one)
    """
    try:
        if output_dir is None:
            output_dir = _get_diagnose_output_dir()

        if not os.path.exists(output_dir):
            return

        for filename in os.listdir(output_dir):
            should_delete = False

            # Check for metadata files: .diagnose_job_{job_id}.json
            if filename.startswith(".diagnose_job_") and filename.endswith(".json"):
                should_delete = True
            # Check for diagnose zip files: diagnose_*.zip
            elif filename.startswith("diagnose_") and filename.endswith(".zip"):
                should_delete = True
            # Check for cluster zip files: cluster_*.zip
            elif filename.startswith("cluster_") and filename.endswith(".zip"):
                should_delete = True

            if should_delete:
                # Skip if this file belongs to the excluded job
                if exclude_job_id and exclude_job_id in filename:
                    continue
                try:
                    filepath = os.path.join(output_dir, filename)
                    os.remove(filepath)
                    logger.info(f"Cleaned up old diagnose file: {filename}", extra={"node": utils.NODE_IP})
                except Exception as e:
                    logger.warning(f"Failed to cleanup {filename}: {e}", extra={"node": utils.NODE_IP})
    except Exception as e:
        logger.warning(f"Failed to cleanup diagnose files: {e}", extra={"node": utils.NODE_IP})


def _find_diagnose_file_by_job_id(job_id, output_dir=None):
    """
    Search for a diagnose zip file by job_id in the filename.

    Filename patterns:
        - diagnose_{job_id}_{timestamp}.zip (standalone)
        - cluster_{job_id}_{timestamp}.zip (HA mode)

    Args:
        job_id: The diagnose job ID to search for
        output_dir: Optional output directory

    Returns:
        tuple: (file_path, file_name) if found, (None, None) otherwise
    """
    try:
        if output_dir is None:
            output_dir = _get_diagnose_output_dir()

        if not os.path.exists(output_dir):
            return None, None

        # Search for files matching the pattern with job_id
        for filename in os.listdir(output_dir):
            if filename.endswith(".zip") and job_id in filename:
                # Verify it matches expected patterns
                if filename.startswith("diagnose_") or filename.startswith("cluster_"):
                    file_path = os.path.join(output_dir, filename)
                    if os.path.exists(file_path):
                        return file_path, filename

        return None, None
    except Exception as e:
        logger.warning(f"Error searching for diagnose file: {e}", extra={"node": utils.NODE_IP})
        return None, None


def _find_latest_diagnose_file(output_dir=None):
    """
    Find the most recent diagnose zip file in the output directory.

    This is used as a fallback when no job_id is provided.

    Args:
        output_dir: Optional output directory

    Returns:
        tuple: (file_path, file_name, job_id) if found, (None, None, None) otherwise
    """
    try:
        if output_dir is None:
            output_dir = _get_diagnose_output_dir()

        if not os.path.exists(output_dir):
            return None, None, None

        latest_file = None
        latest_mtime = 0
        latest_job_id = None

        for filename in os.listdir(output_dir):
            if filename.endswith(".zip") and (filename.startswith("diagnose_") or filename.startswith("cluster_")):
                file_path = os.path.join(output_dir, filename)
                mtime = os.path.getmtime(file_path)
                if mtime > latest_mtime:
                    latest_mtime = mtime
                    latest_file = file_path
                    # Extract job_id from filename: prefix_{job_id}_{timestamp}.zip
                    parts = filename.rsplit("_", 1)[0]  # Remove timestamp.zip
                    if "_" in parts:
                        # Get the UUID part (after prefix_)
                        job_id_part = parts.split("_", 1)[1] if "_" in parts else None
                        # UUID is 36 chars, check if it looks like one
                        if job_id_part and len(job_id_part) >= 36:
                            latest_job_id = job_id_part[:36]

        if latest_file:
            return latest_file, os.path.basename(latest_file), latest_job_id
        return None, None, None
    except Exception as e:
        logger.warning(f"Error finding latest diagnose file: {e}", extra={"node": utils.NODE_IP})
        return None, None, None


def _recover_diagnose_job_state(job_id=None):
    """
    Attempt to recover diagnose job state from file system after restart.

    This function checks for:
    1. Metadata file for the specific job_id (if provided)
    2. Zip file matching the job_id pattern
    3. Latest available diagnose file (if no job_id)

    Args:
        job_id: Optional specific job ID to recover

    Returns:
        dict or None: Recovered job state if found
    """
    output_dir = _get_diagnose_output_dir()

    # Check if output directory exists
    if not os.path.exists(output_dir):
        return None

    # If job_id provided, try to recover that specific job
    if job_id:
        # First check metadata file
        job_data = _load_diagnose_job_metadata(job_id, output_dir)
        if job_data:
            # Verify the file still exists
            file_path = job_data.get("file_path")
            if file_path and os.path.exists(file_path):
                logger.info(f"Recovered diagnose job {job_id} from metadata", extra={"node": utils.NODE_IP})
                return job_data
            # File doesn't exist - clean up stale metadata
            _delete_diagnose_job_metadata(job_id, output_dir)

        # Fallback: search for file by job_id in filename
        file_path, file_name = _find_diagnose_file_by_job_id(job_id, output_dir)
        if file_path:
            recovered_job = {
                "job_id": job_id,
                "status": "completed",
                "message": "Recovered after restart",
                "file_path": file_path,
                "file_name": file_name,
                "error": None,
                "node_summary": None,
            }
            logger.info(f"Recovered diagnose job {job_id} from filename", extra={"node": utils.NODE_IP})
            return recovered_job

    # No specific job_id - search for latest metadata file first (for running jobs)
    latest_metadata_file = None
    latest_metadata_mtime = 0

    try:
        for filename in os.listdir(output_dir):
            if filename.startswith(".diagnose_job_") and filename.endswith(".json"):
                file_path = os.path.join(output_dir, filename)
                mtime = os.path.getmtime(file_path)
                if mtime > latest_metadata_mtime:
                    latest_metadata_mtime = mtime
                    latest_metadata_file = filename

        if latest_metadata_file:
            # Extract job_id from .diagnose_job_{job_id}.json
            extracted_job_id = latest_metadata_file.replace(".diagnose_job_", "").replace(".json", "")

            job_data = _load_diagnose_job_metadata(extracted_job_id, output_dir)
            if job_data:
                # For running jobs, file_path will be None
                if job_data.get("status") == "running":
                    logger.info(f"Recovered running diagnose job {extracted_job_id}", extra={"node": utils.NODE_IP})
                    return job_data
                # For completed jobs, verify file exists
                elif job_data.get("file_path") and os.path.exists(job_data["file_path"]):
                    logger.info(f"Recovered completed diagnose job {extracted_job_id}", extra={"node": utils.NODE_IP})
                    return job_data
                else:
                    _delete_diagnose_job_metadata(extracted_job_id, output_dir)
    except Exception as e:
        logger.warning(f"Error searching metadata files: {e}", extra={"node": utils.NODE_IP})

    # Fallback: search for latest zip file (for completed jobs without metadata)
    file_path, file_name, extracted_job_id = _find_latest_diagnose_file(output_dir)
    if file_path and extracted_job_id:
        # Try to load metadata for this job
        job_data = _load_diagnose_job_metadata(extracted_job_id, output_dir)
        if job_data and job_data.get("file_path") and os.path.exists(job_data["file_path"]):
            logger.info(f"Recovered latest diagnose job {extracted_job_id}", extra={"node": utils.NODE_IP})
            return job_data

        # Clean up stale metadata if file path doesn't match or doesn't exist
        if job_data:
            _delete_diagnose_job_metadata(extracted_job_id, output_dir)

        # Create minimal recovered state
        recovered_job = {
            "job_id": extracted_job_id,
            "status": "completed",
            "message": "Recovered after restart",
            "file_path": file_path,
            "file_name": file_name,
            "error": None,
            "node_summary": None,
        }
        logger.info(f"Recovered latest diagnose job {extracted_job_id} from zip file", extra={"node": utils.NODE_IP})
        return recovered_job

    return None


# SNI-based certificate hot-reload
_cached_ssl_context = None
_cached_cert_mtime = None
_ssl_context_lock = threading.Lock()


def _create_ssl_context_internal(server_cert, server_key, client_ca, sni_callback=None, tls_version="1.3"):
    """Create SSL context with given certificates and TLS version.

    Args:
        server_cert (str): Path to server certificate file.
        server_key (str): Path to server key file.
        client_ca (str): Path to client CA file.
        sni_callback (callable, optional): SNI callback function.
        tls_version (str): TLS version to use ("1.2" or "1.3"). Defaults to "1.3".

    Returns:
        ssl.SSLContext: Configured SSL context with secure cipher suites.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Set minimum TLS version based on configuration
    if tls_version == "1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        logger.info("TLS 1.3 minimum version configured for Management Server", extra={"node": utils.NODE_IP})
    elif tls_version == "1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(TLSV2_CIPHER_STRING)
        logger.info("TLS 1.2 minimum version configured for Management Server", extra={"node": utils.NODE_IP})
    else:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        logger.warning(
            f"Invalid TLS version '{tls_version}' specified, defaulting to TLS 1.3", extra={"node": utils.NODE_IP}
        )

    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.load_verify_locations(cafile=client_ca)
    context.check_hostname = False
    if sni_callback:
        context.sni_callback = sni_callback
    return context


def force_ssl_context_reload(tls_version="1.3"):
    """Force immediate reload of SSL context with new certificates.

    This must be called after generating new certificates and BEFORE
    making any API calls to ensure the server presents the new certs.

    Args:
        tls_version (str): TLS version to use ("1.2" or "1.3"). Defaults to "1.3".
    """
    global _cached_ssl_context, _cached_cert_mtime

    try:
        server_cert, server_key, client_ca = get_certs_locations()

        with _ssl_context_lock:
            # Get the existing SNI callback from current context
            # We need to preserve the SNI callback for future hot-reloads

            if _cached_ssl_context is not None:
                try:
                    _ = _cached_ssl_context.sni_callback
                except Exception:
                    pass

            # Create new SSL context with updated certificates
            # Use the same SNI callback structure as get_ssl_context_with_sni()
            def sni_callback(ssl_socket, server_name, original_context):
                """Hot-reload certificates if file changed."""
                global _cached_ssl_context, _cached_cert_mtime
                try:
                    server_cert, server_key, client_ca = get_certs_locations()
                    current_mtime = os.path.getmtime(server_cert)
                    with _ssl_context_lock:
                        if _cached_cert_mtime is not None and current_mtime > _cached_cert_mtime:
                            new_context = _create_ssl_context_internal(
                                server_cert, server_key, client_ca, sni_callback, tls_version
                            )
                            _cached_ssl_context = new_context
                            _cached_cert_mtime = current_mtime
                            logger.info("Certificate hot-reloaded", extra={"node": utils.NODE_IP})
                            ssl_socket.context = new_context
                        return None
                except Exception as e:
                    logger.error(f"SNI callback error: {e}", extra={"node": utils.NODE_IP})
                    return None

            # Create and cache new SSL context
            new_context = _create_ssl_context_internal(server_cert, server_key, client_ca, sni_callback, tls_version)
            _cached_ssl_context = new_context
            _cached_cert_mtime = os.path.getmtime(server_cert)

            logger.info("SSL context reloaded with new certificates", extra={"node": utils.NODE_IP})
        return True
    except Exception as e:
        logger.error(f"Failed to reload SSL context: {e}", extra={"node": utils.NODE_IP})
        return False


def get_ssl_context_with_sni(tls_version="1.3"):
    """Create SSL context with SNI callback for certificate hot-reload.

    Args:
        tls_version (str): TLS version to use ("1.2" or "1.3"). Defaults to "1.3".

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    global _cached_ssl_context, _cached_cert_mtime

    def sni_callback(ssl_socket, server_name, original_context):
        """Hot-reload certificates if file changed."""
        global _cached_ssl_context, _cached_cert_mtime

        try:
            server_cert, server_key, client_ca = get_certs_locations()
            current_mtime = os.path.getmtime(server_cert)

            with _ssl_context_lock:
                if _cached_cert_mtime is not None and current_mtime > _cached_cert_mtime:
                    new_context = _create_ssl_context_internal(
                        server_cert,
                        server_key,
                        client_ca,
                        sni_callback,
                        tls_version,
                    )
                    _cached_ssl_context = new_context
                    _cached_cert_mtime = current_mtime

                    logger.info("Certificate hot-reloaded", extra={"node": utils.NODE_IP})
                    ssl_socket.context = new_context
                return None

        except Exception as e:
            logger.error(f"SNI callback error: {e}", extra={"node": utils.NODE_IP})
            return None

    server_cert, server_key, client_ca = get_certs_locations()
    context = _create_ssl_context_internal(server_cert, server_key, client_ca, sni_callback, tls_version)

    _cached_ssl_context = context
    _cached_cert_mtime = os.path.getmtime(server_cert)

    return context


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


def get_decrypted_jwt_secret():
    """
    Get the decrypted JWT_SECRET from .env.keys file or config file.

    Returns:
        str: The decrypted JWT secret, or None if not found or decryption fails.
    """
    try:
        # 1. Try from environment variable
        jwt_from_env = os.getenv("JWT_SECRET")
        if jwt_from_env:
            return jwt_from_env

        # 2. Try from AVAILABLE_INPUTS (loaded from .env)
        jwt_from_inputs = AVAILABLE_INPUTS.get("JWT_SECRET")
        if jwt_from_inputs and not AVAILABLE_INPUTS.get("CE_SETUP_ID"):
            return jwt_from_inputs

        # 3. Try to decrypt from .env.keys
        secret_location = AVAILABLE_INPUTS.get("LOCATION") or os.getenv("LOCATION", ".env.keys")
        if os.path.exists(secret_location):
            encrypted_jwt = None
            with open(secret_location, "r") as f:
                for line in f:
                    if line.startswith("JWT_SECRET="):
                        encrypted_jwt = line.strip().split("=", 1)[1]
                        break

            if encrypted_jwt:
                ce_setup_id = (AVAILABLE_INPUTS.get("CE_SETUP_ID") or os.getenv("CE_SETUP_ID", "")).strip('"')
                ce_hex_code = AVAILABLE_INPUTS.get("CE_HEX_CODE") or os.getenv("CE_HEX_CODE", "")
                ce_iv = AVAILABLE_INPUTS.get("CE_IV") or os.getenv("CE_IV", "")

                if all([ce_setup_id, ce_hex_code, ce_iv]):
                    if not AVAILABLE_INPUTS.get("CE_SETUP_ID"):
                        AVAILABLE_INPUTS["CE_SETUP_ID"] = f'"{ce_setup_id}"'
                        AVAILABLE_INPUTS["CE_HEX_CODE"] = ce_hex_code
                        AVAILABLE_INPUTS["CE_IV"] = ce_iv
                    decrypted_jwt = utils.encrypt_decrypt_secret(
                        encrypted_jwt, forward=False, available_inputs=AVAILABLE_INPUTS
                    )
                    if decrypted_jwt:
                        return decrypted_jwt

        # 4. Fallback to config file (secondary node scenarios)
        config = read_config_file(CONFIG_FILE_PATH)
        if config.get("JWT_SECRET"):
            return config.get("JWT_SECRET")

        return jwt_from_inputs
    except Exception:
        try:
            config = read_config_file(CONFIG_FILE_PATH)
            return config.get("JWT_SECRET")
        except Exception:
            return AVAILABLE_INPUTS.get("JWT_SECRET")


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
        for message in execute_command(command, env=env, shell=shell, input_data=input_data):
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
                logger.error(f"Parsing error in loadavg: {e}", extra={"node": utils.NODE_IP})
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
                f"Error encountered while fetching memory information from /proc/meminfo. {result['message']}",
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
        raise ClientExceptions(
            "Unauthorized Error. "
            "Please ensure configured JWT_SECRET is same as Primary Node's JWT_SECRET before executing CE Setup."
        )
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

        def strip_control_chars(s):
            # overridden.
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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, PATCH, OPTIONS")
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

                        # If handler returns None, it has already sent the response (e.g., file streaming)
                        if response is None:
                            return

                        response = json.dumps(response).encode()
                    except Exception as e:
                        logger.error(
                            f"Error handling request for {self.path}. Error: {str(e)} "
                            f"Traceback: {traceback.format_exc()}",
                            extra={"node": utils.NODE_IP},
                        )
                        response = json.dumps(
                            {"details": f"Error handling request for {self.path}. Error: {str(e)}"}
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
                f"Error handling request for {self.path}. Error: {str(e)} Traceback: {traceback.format_exc()}",
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
            SECRET_KEY = get_decrypted_jwt_secret()
        if SECRET_KEY is None or SECRET_KEY == "":
            logger.error(
                "JWT_SECRET is not set in the environment variable or config file.",
                extra={"node": utils.NODE_IP},
            )
            raise Exception("JWT_SECRET is not set in the environment variable or config file.")
        auth_header = self.headers.get("Authorization")
        if auth_header and (auth_header.startswith("Bearer ") or auth_header.startswith("bearer ")):
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
            expected_sig = hmac.new(SECRET_KEY.encode(), message, JWT_ALGORITH_LIB_MAP[JWT_ALGORITH]).digest()
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
        encoded_header = base64.urlsafe_b64encode(json.dumps(header_dict).encode("utf-8")).decode().rstrip("=")

        payload_dict = {
            "username": payload.get("username", DEFAULT_USER),
            "scopes": payload.get("scopes", []),
            "type": "service-access",
            "exp": int((datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        }
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode("utf-8")).decode().rstrip("=")
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        signature_binary = hmac.new(
            SECRET_KEY.encode(),
            signing_input,
            JWT_ALGORITH_LIB_MAP[JWT_ALGORITH],
        ).digest()
        encoded_signature = base64.urlsafe_b64encode(signature_binary).decode().rstrip("=")
        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"
    except Exception as e:
        logger.error(f"encountered error while creating token: {e} {traceback.format_exc()}")
        return None


def get_certs_locations():
    """Get the locations of the server certificate, server private key, and client CA certificate."""
    server_cert = CERT_DIR + "tls_cert.crt"  # Server certificate
    server_key = CERT_DIR + "tls_cert_key.key"  # Server private key
    client_ca = CERT_DIR + "tls_cert_ca.crt"  # CA certificate that signed client certificates
    if not os.path.exists(server_cert) or not os.path.exists(server_key) or not os.path.exists(client_ca):
        raise Exception("SSL certificates not found.")

    return server_cert, server_key, client_ca


def get_tls_version():
    """Get the TLS version from configuration.

    Returns:
        str: The TLS version to use ("1.2" or "1.3"). Defaults to "1.3" if not configured.
    """
    # Load environment variables with proper priority: cloudexchange.config → .env → default
    success, error_msg = load_environment_from_multiple_sources(handler=None)
    if not success:
        logger.error(f"Failed to load environment: {error_msg}", extra={"node": utils.NODE_IP})

    utils.read_cloud_exchange_config_file()
    tls_version_config = utils.CLOUD_EXCHANGE_CONFIG.get("TLS_VERSION")

    if not tls_version_config:
        tls_version_config = AVAILABLE_INPUTS.get("TLS_VERSION")

    if not tls_version_config:
        tls_version_config = "1.3"

    tls_version_config = str(tls_version_config).strip().strip('"').strip("'")
    tls_version_config = tls_version_config.upper().replace("TLSV", "")

    # Parse TLS version - handle both single version ("1.3") and multiple versions ("1.2,1.3")
    # When multiple versions are specified, use the minimum version as the baseline
    tls_version_config = tls_version_config.replace(" ", ",")
    if "," in tls_version_config:
        versions = [v.strip() for v in str(tls_version_config).split(",")]
        # Filter valid versions and sort to get minimum
        valid_versions = [v for v in versions if v in ["1.2", "1.3"]]
        if valid_versions:
            tls_version = min(valid_versions)  # "1.2" < "1.3" in string comparison
            logger.info(
                f"Multiple TLS versions specified: {tls_version_config}. Using minimum version: {tls_version}",
                extra={"node": utils.NODE_IP},
            )
        else:
            tls_version = "1.3"
            logger.warning(
                f"No valid TLS versions found in config: {tls_version_config}. Defaulting to TLS 1.3",
                extra={"node": utils.NODE_IP},
            )
    else:
        tls_version = str(tls_version_config).strip()

    return tls_version


def run(server_class=HTTPServer, handler_class=SimpleAPIServer):
    """Run the API server with certificate hot-reload and configured TLS version."""
    server_cert, server_key, client_ca = get_certs_locations()

    if not os.path.exists(server_cert) or not os.path.exists(server_key) or not os.path.exists(client_ca):
        raise Exception("Certificates not found.")

    port = int(os.getenv("CE_MANAGEMENT_PORT", 8000))
    server_address = ("0.0.0.0", port)
    httpd = server_class(server_address, handler_class)

    # Use SSL context with SNI callback for automatic certificate hot-reload
    # This enables loading new certificates without server restart
    tls_version = get_tls_version()
    context = get_ssl_context_with_sni(tls_version=tls_version)

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=True)

    logger.info(f"Server running at https://{server_address[0]}:{server_address[1]} (with certificate hot-reload)")
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
            should_proceed = True

    if not should_proceed or errors:
        return {"detail": "Invalid data provided", "errors": errors}, 400

    if env_file:
        env_file_path = env_file
    elif AVAILABLE_INPUTS.get("ENV_FILE"):
        env_file_path = AVAILABLE_INPUTS.get("ENV_FILE")
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
                            "MAINTENANCE_PASSWORD_ESCAPED": urllib.parse.quote_plus(value),
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
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE") is not None and ip != AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
    ) or ip != utils.NODE_IP:
        logger.info(f"Starting Cloud Exchange on Node {ip}", extra={"node": utils.NODE_IP})
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
            return {"detail": f"Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}"}, 500
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
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE") is not None and ip != AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
    ) or ip != utils.NODE_IP:
        logger.info(f"Stopping Cloud Exchange on Node {ip}", extra={"node": utils.NODE_IP})
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
            return {"detail": f"Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}"}, 500
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
        response = stop_ce(handler=handler, should_end_stream=False, as_api=False, ip=ip)
        if response[1] != 200:
            end_stream(handler=handler)
            return response
        response = start_ce(handler=handler, should_end_stream=False, as_api=False, ip=ip)
        if response[1] != 200:
            end_stream(handler=handler)
            return response
        write_chunk(handler.wfile, "Info: Cloud Exchange restarted.\n")
    except Exception as e:
        logger.error(f"Error Restarting the Cloud Exchange: {e}", extra={"node": utils.NODE_IP})
        write_chunk(handler.wfile, f"End: Error Restarting the Cloud Exchange: {str(e)}\n")
        end_stream(handler=handler)
        return {"detail": f"Error Restarting the Cloud Exchange: {str(e)}"}, 500
    finally:
        end_stream(handler=handler)
    return {"detail": "Restarted Cloud Exchange successfully."}, 200


def generate_self_signed_certificates(cert_dir=CERT_DIR, validity_days=365):
    """
    Generate self-signed TLS certificates for MongoDB and RabbitMQ.

    Args:
        cert_dir (str): The directory to store certificates.
        validity_days (int): Certificate validity in days (1-365).

    Raises:
        ValueError: If validity_days is out of range.
        RuntimeError: If certificate generation fails.
    """
    if not isinstance(validity_days, int) or not 1 <= validity_days <= 365:
        raise ValueError(f"validity_days must be between 1 and 365, got {validity_days}")

    try:
        os.makedirs(cert_dir, exist_ok=True)

        cert_file = os.path.join(cert_dir, "tls_cert.crt")
        key_file = os.path.join(cert_dir, "tls_cert_key.key")
        pem_file = os.path.join(cert_dir, "tls_cert_key.pem")
        ca_key = os.path.join(cert_dir, "tls_cert_ca.key")
        ca_crt = os.path.join(cert_dir, "tls_cert_ca.crt")
        csr_file = os.path.join(cert_dir, "tls_cert.csr")

        extendedkeyusage_conf = "./data/ssl_certs/mongodb_rabbitmq_certs/extendedkeyusage.txt"
        common_ca_conf = "./data/ssl_certs/mongodb_rabbitmq_certs/common_ca.conf"

        if not os.path.exists(extendedkeyusage_conf):
            raise RuntimeError(f"Extended key usage config not found at {extendedkeyusage_conf}")
        if not os.path.exists(common_ca_conf):
            raise RuntimeError(f"Common CA config not found at {common_ca_conf}")

        # Generate CA key if not exists
        if not os.path.exists(ca_key):
            result = subprocess.run(
                ["openssl", "genrsa", "-out", ca_key, "4096"], capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                raise RuntimeError(f"Failed to generate CA key: {result.stderr}")

        # Always regenerate CA certificate during renewal to ensure full certificate chain renewal
        logger.info("Generating new CA certificate...", extra={"node": utils.NODE_IP})
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-nodes",
                "-key",
                ca_key,
                "-sha256",
                "-days",
                str(validity_days),
                "-out",
                ca_crt,
                "-subj",
                "/CN=CloudExchangeCA",
                "-extensions",
                "v3_ca",
                "-config",
                common_ca_conf,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to generate CA certificate: {result.stderr}")

        # Generate CSR
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:4096",
                "-nodes",
                "-keyout",
                key_file,
                "-out",
                csr_file,
                "-config",
                extendedkeyusage_conf,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to generate CSR: {result.stderr}")

        # Sign CSR with CA
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                csr_file,
                "-CA",
                ca_crt,
                "-CAkey",
                ca_key,
                "-CAcreateserial",
                "-out",
                cert_file,
                "-days",
                str(validity_days),
                "-extfile",
                extendedkeyusage_conf,
                "-extensions",
                "req_ext",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to sign certificate: {result.stderr}")

        # Create combined PEM file for MongoDB
        with open(pem_file, "wb") as pem_out:
            with open(cert_file, "rb") as cert_in:
                shutil.copyfileobj(cert_in, pem_out)
            with open(key_file, "rb") as key_in:
                shutil.copyfileobj(key_in, pem_out)

        # Set secure permissions using helper function
        set_certificate_permissions(cert_dir)

        logger.info(
            f"Certificates generated successfully with {validity_days} days validity", extra={"node": utils.NODE_IP}
        )
    except Exception as e:
        logger.error(f"Error generating certificates: {e}", extra={"node": utils.NODE_IP})
        raise RuntimeError(f"Error generating certificates: {e}")


def renew_ui_certificate_if_https(validity_days=365):
    """Regenerate the UI TLS certificate when UI protocol is HTTPS.

    Args:
        validity_days (int): Certificate validity in days.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        cert_dir = "./data/ssl_certs"
        cert_file = os.path.join(cert_dir, "cte_cert.crt")
        key_file = os.path.join(cert_dir, "cte_cert_key.key")
        extendedkeyusage_conf = os.path.join(cert_dir, "extendedkeyusage.txt")

        if not os.path.exists(extendedkeyusage_conf):
            raise RuntimeError(f"Extended key usage config not found at {extendedkeyusage_conf}")

        result = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-keyout",
                key_file,
                "-out",
                cert_file,
                "-sha256",
                "-days",
                str(validity_days),
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-extensions",
                "extendedkeyusage",
                "-config",
                extendedkeyusage_conf,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr)

        try:
            os.chmod(cert_file, 0o644)
            os.chmod(key_file, 0o644)
        except Exception as e:
            logger.warning(
                f"Failed to adjust permissions on UI certificate files: {e}",
                extra={"node": utils.NODE_IP},
            )

        logger.info(
            f"UI certificate renewed successfully with {validity_days} days validity",
            extra={"node": utils.NODE_IP},
        )
        return True
    except Exception as e:
        logger.error(
            f"Error renewing UI certificate: {e}",
            extra={"node": utils.NODE_IP},
        )
        return False


def is_ce_managed_certificate(cert_file):
    """Return True if cert_file is generated by CE.

    Args:
        cert_file (str): Path to certificate file.

    Returns:
        bool: True if certificate is CE-generated, False if custom.
    """
    try:
        if not os.path.exists(cert_file):
            return False

        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-noout", "-issuer"],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0:
            issuer = result.stdout.strip().replace("issuer=", "").strip().replace(" ", "")
            return "CN=CloudExchangeCA" in issuer or "CN=localhost" in issuer

        return False
    except Exception as e:
        logger.error(
            f"Error while checking if certificate is CE-managed for {cert_file}: {e}",
            extra={"node": utils.NODE_IP},
        )
        return False


def get_all_node_ips():
    """Get all node IPs from HA configuration."""
    try:
        ha_enabled = str(AVAILABLE_INPUTS.get("HA_ENABLED", False)).lower() in ("true", "1")

        if ha_enabled and AVAILABLE_INPUTS.get("HA_IP_LIST"):
            ip_list = [ip.strip() for ip in AVAILABLE_INPUTS["HA_IP_LIST"].split(",") if ip.strip()]
            return ip_list if ip_list else [utils.NODE_IP]

        return [utils.NODE_IP]
    except Exception as e:
        logger.error(f"Error getting all node IPs: {e}", extra={"node": utils.NODE_IP})
        return [utils.NODE_IP]


def get_nodes_requiring_renewal():
    """Return list of node IPs whose certificates should be renewed and what to renew.

    Returns:
        tuple: (node_ips: list, renew_ca: bool, renew_ui: bool)
    """
    ca_cert_file = os.path.join(CERT_DIR, "tls_cert.crt")
    ui_cert_file = "./data/ssl_certs/cte_cert.crt"

    ca_is_ce_managed = is_ce_managed_certificate(ca_cert_file)
    ui_is_ce_managed = is_ce_managed_certificate(ui_cert_file)

    # Apply renewal logic based on management status
    if not ca_is_ce_managed and ui_is_ce_managed:
        return get_all_node_ips(), False, True
    elif ca_is_ce_managed and not ui_is_ce_managed:
        return get_all_node_ips(), True, False
    elif not ca_is_ce_managed and not ui_is_ce_managed:
        logger.info("Both CA and UI certificates are custom, skipping renewal", extra={"node": utils.NODE_IP})
        return [], False, False
    elif ca_is_ce_managed and ui_is_ce_managed:
        return get_all_node_ips(), True, True

    return [], False, False


def is_management_server_reachable(handler, node_ip, protocol="https"):
    """Check if the management server is reachable on the specified node.

    Args:
        handler: The request handler object.
        node_ip (str): The IP address of the node to check.
        protocol (str): The protocol to use (http/https).

    Returns:
        tuple: (is_reachable: bool, error_message: str or None)
    """
    try:
        # Local node is always reachable if this code is running
        if node_ip == utils.NODE_IP:
            return True, None

        # Use the node-details endpoint as a health check for remote nodes
        for response in check_management_server(
            node_ip=node_ip,
            handler=handler,
            endpoint="/api/management/node-details",
            method="GET",
            protocol=protocol,
            should_stream=False,
        ):
            if isinstance(response, tuple) and len(response) >= 2:
                if response[1] == 200:
                    return True, None
                else:
                    return False, f"Management server returned status {response[1]}"
            elif isinstance(response, dict):
                return True, None
        return True, None
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Management server at {node_ip} is unreachable: {error_msg}", extra={"node": utils.NODE_IP})
        return False, error_msg


@SimpleAPIServer.route("/ce-status", methods=["GET"], scopes=[ME_ROLE])
def ce_status_endpoint(handler):
    """Get the CE container running status on the local node.

    Returns:
        dict: A dictionary containing:
            - is_running: bool indicating if CE containers are running
            - node_ip: The IP of this node
    """
    try:
        fetch_container_info()
        # CE is considered running only if ALL core containers are running
        is_running = utils.is_ui_running and utils.is_rabbitmq_running and utils.is_mongodb_running
        return {
            "is_running": is_running,
            "node_ip": utils.NODE_IP,
            "containers": {
                "ui": utils.is_ui_running,
                "rabbitmq": utils.is_rabbitmq_running,
                "mongodb": utils.is_mongodb_running,
            },
        }, 200
    except Exception as e:
        logger.error(f"Error getting CE status: {e}", extra={"node": utils.NODE_IP})
        return {"detail": str(e), "is_running": False, "node_ip": utils.NODE_IP}, 500


def get_remote_ce_status(handler, node_ip, protocol="https"):
    """Get the CE container running status on a node (local or remote).

    Args:
        handler: The request handler object.
        node_ip (str): The IP address of the node to check.
        protocol (str): The protocol to use for remote calls.

    Returns:
        tuple: (is_running: bool, error_message: str or None)
    """
    try:
        # If checking local node, use direct container check
        if node_ip == utils.NODE_IP:
            fetch_container_info()
            is_running = utils.is_ui_running and utils.is_rabbitmq_running and utils.is_mongodb_running
            return is_running, None

        # For remote nodes, use API call
        for response in check_management_server(
            node_ip=node_ip,
            handler=handler,
            endpoint="/api/management/ce-status",
            method="GET",
            protocol=protocol,
            should_stream=False,
        ):
            if isinstance(response, tuple) and len(response) >= 2:
                if response[1] == 200 and isinstance(response[0], dict):
                    return response[0].get("is_running", False), None
                else:
                    return False, f"Failed to get CE status: {response}"
            elif isinstance(response, dict):
                return response.get("is_running", False), None
        return False, "No response from remote node"
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error getting CE status from {node_ip}: {error_msg}", extra={"node": utils.NODE_IP})
        return False, error_msg


def set_certificate_permissions(cert_dir):
    """Set file permissions for certificates."""
    try:
        # Private files - only owner can read (CA key should never be mounted)
        private_files = ["tls_cert_ca.key"]
        # Public/container-accessible files - need 644 for Docker containers running as non-root users
        # tls_cert_key.key is mounted into RabbitMQ container which runs as user 1001:1001
        # tls_cert_key.pem is mounted into MongoDB container which runs as non-root user
        public_files = ["tls_cert.crt", "tls_cert_ca.crt", "tls_cert_key.pem", "tls_cert_key.key"]

        for filename in private_files:
            filepath = os.path.join(cert_dir, filename)
            if os.path.exists(filepath):
                os.chmod(filepath, 0o600)

        for filename in public_files:
            filepath = os.path.join(cert_dir, filename)
            if os.path.exists(filepath):
                os.chmod(filepath, 0o644)
    except Exception as e:
        logger.warning(f"Failed to set certificate permissions: {e}", extra={"node": utils.NODE_IP})


def copy_and_set_permissions_ha(handler, is_primary, ha_nfs_dir, is_https_ui, renew_ca=True, renew_ui=True):
    """Copy certificates to/from shared storage and set permissions.

    Args:
        handler: Request handler
        is_primary: Whether this is the primary node
        ha_nfs_dir: HA NFS directory path
        is_https_ui: Whether UI is using HTTPS
        renew_ca: Whether to copy CA/DB/RabbitMQ certificates
        renew_ui: Whether to copy UI certificates
    """
    shared_cert_dir = f"{ha_nfs_dir}/config/ssl_certs/mongodb_rabbitmq_certs"
    shared_ui_cert_dir = f"{ha_nfs_dir}/config/ssl_certs"

    try:
        if is_primary:
            cmd = f"{SUDO_PREFIX} mkdir -p {shared_cert_dir} {shared_ui_cert_dir}"
            response = execute_command_with_logging(
                cmd, handler, should_end_stream=False, shell=True, message="creating shared directories"
            )
            if response[1] != 200:
                return False, "Failed to create shared directories"

            cmd = f"{SUDO_PREFIX} chmod -R 755 {ha_nfs_dir}/config"
            execute_command(cmd, shell=True)

            if renew_ca:
                cmd = f"{SUDO_PREFIX} cp -f {os.path.abspath(CERT_DIR)}/* {shared_cert_dir}/"
                response = execute_command_with_logging(
                    cmd, handler, should_end_stream=False, shell=True, message="copying CA certificates"
                )
                if response[1] != 200:
                    return False, "Failed to copy DB/RabbitMQ certificates"

                # Set 644 on all container-accessible files (RabbitMQ runs as user 1001:1001)
                # Only tls_cert_ca.key should be 600 (not mounted into containers)
                cmd = (
                    f"{SUDO_PREFIX} sh -c 'chmod 644 {shared_cert_dir}/*.crt {shared_cert_dir}/*.pem "
                    f"{shared_cert_dir}/tls_cert_key.key 2>/dev/null; "
                    f"chmod 600 {shared_cert_dir}/tls_cert_ca.key 2>/dev/null'"
                )
                execute_command(cmd, shell=True)

            if renew_ui and is_https_ui:
                cmd = f"{SUDO_PREFIX} chmod 644 ./data/ssl_certs/cte_cert.crt ./data/ssl_certs/cte_cert_key.key"
                execute_command(cmd, shell=True)

                cmd = (
                    f"{SUDO_PREFIX} cp -f ./data/ssl_certs/cte_cert.crt "
                    f"./data/ssl_certs/cte_cert_key.key {shared_ui_cert_dir}/"
                )
                response = execute_command_with_logging(
                    cmd, handler, should_end_stream=False, shell=True, message="copying UI certificates"
                )
                if response[1] != 200:
                    return False, "Failed to copy UI certificates"

                cmd = f"{SUDO_PREFIX} chmod 644 {shared_ui_cert_dir}/cte_cert.crt {shared_ui_cert_dir}/cte_cert_key.key"
                execute_command(cmd, shell=True)
        else:
            if renew_ca:
                cmd = f"{SUDO_PREFIX} cp -f {shared_cert_dir}/* ./data/ssl_certs/mongodb_rabbitmq_certs/"
                response = execute_command_with_logging(
                    cmd, handler, should_end_stream=False, shell=True, message="syncing CA certificates"
                )
                if response[1] != 200:
                    return False, "Failed to sync DB/RabbitMQ certificates"

                # Set 644 on all container-accessible files (RabbitMQ runs as user 1001:1001)
                # Only tls_cert_ca.key should be 600 (not mounted into containers)
                cmd = (
                    f"{SUDO_PREFIX} sh -c 'chmod 644 ./data/ssl_certs/mongodb_rabbitmq_certs/*.crt "
                    "./data/ssl_certs/mongodb_rabbitmq_certs/*.pem "
                    "./data/ssl_certs/mongodb_rabbitmq_certs/tls_cert_key.key "
                    "2>/dev/null; chmod 600 ./data/ssl_certs/mongodb_rabbitmq_certs/tls_cert_ca.key 2>/dev/null'"
                )
                execute_command(cmd, shell=True)

            if renew_ui and is_https_ui:
                cmd = f"{SUDO_PREFIX} mkdir -p ./data/ssl_certs"
                execute_command(cmd, shell=True)

                cmd = (
                    f"{SUDO_PREFIX} cp -f {shared_ui_cert_dir}/cte_cert.crt "
                    f"{shared_ui_cert_dir}/cte_cert_key.key ./data/ssl_certs/"
                )
                response = execute_command_with_logging(
                    cmd, handler, should_end_stream=False, shell=True, message="syncing UI certificates"
                )
                if response[1] != 200:
                    return False, "Failed to sync UI certificates"

                cmd = f"{SUDO_PREFIX} chmod 644 ./data/ssl_certs/cte_cert.crt ./data/ssl_certs/cte_cert_key.key"
                execute_command(cmd, shell=True)

                cmd = (
                    f"{SUDO_PREFIX} sh -c 'chown $(stat -c %u:%g ./data/ssl_certs) "
                    "./data/ssl_certs/cte_cert*.* 2>/dev/null || true'"
                )
                execute_command(cmd, shell=True)

                if not os.path.exists("./data/ssl_certs/cte_cert.crt") or not os.path.exists(
                    "./data/ssl_certs/cte_cert_key.key"
                ):
                    logger.error("UI certificates not found after sync", extra={"node": utils.NODE_IP})
                    return False, "UI certificates not found after sync"

        if renew_ca:
            required_files = ["tls_cert.crt", "tls_cert_key.key", "tls_cert_key.pem", "tls_cert_ca.crt"]
            for filename in required_files:
                filepath = os.path.join("./data/ssl_certs/mongodb_rabbitmq_certs/", filename)
                if not os.path.exists(filepath):
                    logger.error(f"Required certificate file {filename} not found", extra={"node": utils.NODE_IP})
                    return False, f"Required certificate file {filename} not found"

        return True, None
    except Exception as e:
        return False, str(e)


@SimpleAPIServer.route("/sync-certs", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def sync_certificates(handler):
    """Sync certificates from shared storage to local storage."""
    try:
        success, error_msg = load_environment_from_multiple_sources(handler)
        if not success:
            write_chunk(handler.wfile, "End: Error loading environment variables.")
            end_stream(handler)
            return {"details": error_msg}, 500

        # Get renewal flags from request body
        renew_ca = True
        renew_ui = True
        try:
            content_length = int(handler.headers.get("Content-Length", 0))
            if content_length > 0:
                body = handler.rfile.read(content_length).decode()
                data = json.loads(body)
                renew_ca = data.get("renew_ca", True)
                renew_ui = data.get("renew_ui", True)
        except (json.JSONDecodeError, AttributeError):
            pass  # Use defaults

        ha_nfs_dir = AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY", "/opt/shared/data")
        is_https_ui = AVAILABLE_INPUTS.get("UI_PROTOCOL", "http").lower().strip() == "https"

        success, error_msg = copy_and_set_permissions_ha(handler, False, ha_nfs_dir, is_https_ui, renew_ca, renew_ui)
        if not success:
            write_chunk(handler.wfile, f"End: {error_msg}\n")
            end_stream(handler)
            return {"detail": error_msg}, 500

        end_stream(handler)
        return {"detail": "Certificates synced"}, 200
    except Exception as e:
        write_chunk(handler.wfile, f"End: {str(e)}\n")
        end_stream(handler)
        return {"detail": str(e)}, 500


@SimpleAPIServer.route("/reload-certs", methods=["POST"], scopes=[ADMIN_ROLE])
def reload_certs_endpoint(handler, ip=None, as_api=True):
    """Signal certificates for hot-reload."""
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return {"details": error_msg}, 500

    if as_api:
        try:
            content_length = int(handler.headers.get("Content-Length", 0))
            if content_length > 0:
                body = handler.rfile.read(content_length).decode()
                data = json.loads(body)
                ip = data.get("node_ip", "").strip()
        except (json.JSONDecodeError, AttributeError):
            pass

    if not ip:
        ip = utils.NODE_IP

    if (
        AVAILABLE_INPUTS.get("HA_CURRENT_NODE") is not None and ip != AVAILABLE_INPUTS.get("HA_CURRENT_NODE")
    ) or ip != utils.NODE_IP:
        logger.info(f"Reloading certificates on Node {ip}", extra={"node": utils.NODE_IP})
        try:
            for response_chunk in check_management_server(
                handler=handler,
                endpoint="/api/management/reload-certs",
                node_ip=ip,
                method="POST",
                protocol=AVAILABLE_INPUTS["UI_PROTOCOL"],
                should_stream=False,
            ):
                pass
            return {"detail": "Certificates reloaded", "node_ip": ip}, 200
        except Exception as e:
            return {"detail": f"Error reloading certificates on Node {ip}: {str(e)}", "node_ip": ip}, 500
    else:
        logger.info("Reloading certificates on local node", extra={"node": utils.NODE_IP})
        try:
            success, message = reload_ssl_certificates()
            if success:
                return {
                    "detail": "Certificates ready for hot-reload",
                    "message": message,
                    "node_ip": utils.NODE_IP,
                }, 200
            else:
                return {"detail": message, "node_ip": utils.NODE_IP}, 500
        except Exception as e:
            logger.error(f"Error in reload-certs endpoint: {e}", extra={"node": utils.NODE_IP})
            return {"detail": str(e), "node_ip": utils.NODE_IP}, 500


def reload_ssl_certificates():
    """Signal certificates for hot-reload on next connection."""
    try:
        server_cert = CERT_DIR + "tls_cert.crt"
        cert_expiry = "unknown"
        cert_serial = "unknown"

        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", server_cert, "-noout", "-enddate", "-serial"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.startswith("notAfter="):
                        cert_expiry = line.replace("notAfter=", "")
                    elif line.startswith("serial="):
                        cert_serial = line.replace("serial=", "")
        except Exception:
            pass

        return True, f"Certificates ready. Serial={cert_serial}, Expires={cert_expiry}"

    except Exception as e:
        logger.error(f"Certificate reload failed: {e}", extra={"node": utils.NODE_IP})
        return False, str(e)


@SimpleAPIServer.route("/renew-certs", methods=["POST"], stream=True, scopes=[ADMIN_ROLE])
def renew_certificates(handler):
    """Renew TLS certificates for MongoDB, RabbitMQ, and UI.

    Handles three scenarios with state preservation:
    1. Standalone: Generate certs locally, restart CE only if it was running
    2. HA - Primary triggers: Generate certs, copy to NFS, sync to secondary nodes,
       only restart nodes that were previously running
    3. HA - Secondary triggers: Forward request to primary node which handles
       the full cluster renewal

    Key Behavior:
    - Pre-checks management server reachability on all nodes before proceeding
    - Preserves the stopped state: If CE was stopped before renewal, it remains stopped
    - Primary Node (if stopped): Generate certs, copy to NFS, do not restart
    - Secondary Node (if stopped): Sync certs from NFS, do not restart
    """
    stream_ended = False
    try:
        success, error_msg = load_environment_from_multiple_sources(handler)
        if not success:
            write_chunk(handler.wfile, f"End: Failed to load environment: {error_msg}\n")
            end_stream(handler)
            stream_ended = True
            return {"details": error_msg}, 500

        nodes_to_renew, renew_ca, renew_ui = get_nodes_requiring_renewal()
        if not nodes_to_renew:
            write_chunk(handler.wfile, "No CE-managed certificates found. Nothing to renew.\n")
            end_stream(handler=handler)
            stream_ended = True
            return {"detail": "No CE-managed certificates found"}, 200

        is_ha_enabled = str(AVAILABLE_INPUTS.get("HA_ENABLED", False)).lower() in ("true", "1")
        primary_node_ip = AVAILABLE_INPUTS.get("HA_PRIMARY_NODE_IP", utils.NODE_IP)
        is_primary_node = utils.NODE_IP == primary_node_ip
        is_https_ui = AVAILABLE_INPUTS.get("UI_PROTOCOL", "http").lower().strip() == "https"
        protocol = AVAILABLE_INPUTS.get("UI_PROTOCOL", "https")
        validity_days = 365

        # Get list of secondary nodes for HA
        secondary_nodes = [ip for ip in nodes_to_renew if ip != primary_node_ip] if is_ha_enabled else []

        # ============================================================
        # PRE-CHECK: Verify management server reachability on all nodes
        # ============================================================
        if is_ha_enabled:
            write_chunk(handler.wfile, "Verifying management server connectivity...\n")

            # Check primary node if we're not on primary
            if not is_primary_node:
                is_reachable, error = is_management_server_reachable(handler, primary_node_ip, protocol)
                if not is_reachable:
                    error_msg = (
                        f"Primary node ({primary_node_ip}) unreachable. "
                        f"Start management service before renewal certificate."
                    )
                    write_chunk(handler.wfile, f"End: {error_msg}\n")
                    end_stream(handler=handler)
                    stream_ended = True
                    logger.error(error_msg, extra={"node": utils.NODE_IP})
                    return {"detail": error_msg}, 503

            # Check all secondary nodes
            for node_ip in secondary_nodes:
                is_reachable, error = is_management_server_reachable(handler, node_ip, protocol)
                if not is_reachable:
                    error_msg = (
                        f"Secondary node ({node_ip}) unreachable. Start management service before renewal certificate."
                    )
                    write_chunk(handler.wfile, f"End: {error_msg}\n")
                    end_stream(handler=handler)
                    stream_ended = True
                    logger.error(error_msg, extra={"node": utils.NODE_IP})
                    return {"detail": error_msg}, 503

            write_chunk(handler.wfile, "All nodes are reachable\n")

        # ============================================================
        # CHECK CE STATUS: Record which nodes have CE running vs stopped
        # ============================================================
        node_ce_status = {}  # {node_ip: bool} - True if CE was running
        write_chunk(handler.wfile, "Checking CE status on all nodes...\n")

        # Check all nodes CE status (both HA and standalone)
        for node_ip in nodes_to_renew:
            remote_running, error = get_remote_ce_status(handler, node_ip, protocol)
            node_ce_status[node_ip] = remote_running

        # Log CE status summary
        running_nodes = [ip for ip, status in node_ce_status.items() if status]
        stopped_nodes = [ip for ip, status in node_ce_status.items() if not status]
        if running_nodes:
            write_chunk(handler.wfile, f"CE running on: {', '.join(running_nodes)}\n")
        if stopped_nodes:
            write_chunk(handler.wfile, f"CE stopped on: {', '.join(stopped_nodes)}\n")

        # ============================================================
        # Scenario 3: HA - Secondary node triggers -> Forward to primary
        # ============================================================
        if is_ha_enabled and not is_primary_node:
            write_chunk(handler.wfile, f"Forwarding request to primary node ({primary_node_ip})...\n")
            try:
                for response_chunk in check_management_server(
                    handler=handler,
                    endpoint="/api/management/renew-certs",
                    node_ip=primary_node_ip,
                    method="POST",
                    protocol=protocol,
                    should_stream=True,
                ):
                    write_chunk(handler.wfile, response_chunk, node_ip=primary_node_ip)

                end_stream(handler=handler)
                stream_ended = True
                return {"detail": "Certificate renewal completed"}, 200
            except Exception as e:
                write_chunk(handler.wfile, f"End: Failed to forward request to primary node: {str(e)}\n")
                end_stream(handler=handler)
                stream_ended = True
                return {"detail": str(e)}, 500

        # ============================================================
        # PHASE 1: Stop ALL nodes that are running (BEFORE cert generation)
        # ============================================================
        nodes_to_restart = []  # Track which nodes need to be restarted

        if any(node_ce_status.values()):
            write_chunk(handler.wfile, "Stopping CE on all running nodes...\n")

            # Stop all running nodes (primary first, then secondary)
            all_nodes = [primary_node_ip] + secondary_nodes if is_ha_enabled else [primary_node_ip]
            for node_ip in all_nodes:
                if node_ce_status.get(node_ip, False):
                    write_chunk(handler.wfile, f"Stopping CE on {node_ip}...\n")
                    nodes_to_restart.append(node_ip)

                    try:
                        stop_failed = False
                        for response_chunk in check_management_server(
                            handler=handler,
                            endpoint="/api/management/stop-ce",
                            node_ip=node_ip,
                            method="POST",
                            protocol=protocol,
                            should_stream=True,
                            payload={"node_ip": node_ip},
                        ):
                            if response_chunk.strip().upper().startswith("END:"):
                                stop_failed = True
                            write_chunk(handler.wfile, response_chunk, node_ip=node_ip)

                        if stop_failed:
                            write_chunk(handler.wfile, f"End: Failed to stop {node_ip}\n")
                            end_stream(handler=handler)
                            stream_ended = True
                            return {"detail": f"Failed to stop {node_ip}"}, 500
                    except Exception as e:
                        write_chunk(handler.wfile, f"End: Error stopping {node_ip}: {str(e)}\n")
                        end_stream(handler=handler)
                        stream_ended = True
                        return {"detail": f"Error stopping {node_ip}: {str(e)}"}, 500

        # Wait for services to fully stop
        if nodes_to_restart:
            write_chunk(handler.wfile, "Waiting for services to fully stop...\n")
            # time.sleep(5)

            # Verify all nodes are actually stopped
            for node_ip in nodes_to_restart:
                is_running, _ = get_remote_ce_status(handler, node_ip, protocol)
                if is_running:
                    write_chunk(handler.wfile, f"End: {node_ip} still running after stop command\n")
                    end_stream(handler=handler)
                    stream_ended = True
                    return {"detail": f"{node_ip} failed to stop completely"}, 500

        # ============================================================
        # PHASE 2: Generate new certificates (After stopping CE)
        # ============================================================
        write_chunk(handler.wfile, f"Generating new certificates (validity: {validity_days} days)...\n")
        try:
            if renew_ca:
                generate_self_signed_certificates(CERT_DIR, validity_days)
                write_chunk(handler.wfile, "CA certificates generated successfully\n")
            if renew_ui and is_https_ui:
                renew_ui_certificate_if_https(validity_days)
                write_chunk(handler.wfile, "UI certificates generated successfully\n")
            if not renew_ca and not renew_ui:
                write_chunk(handler.wfile, "No certificates to generate\n")

            # Allow time for filesystem sync
            time.sleep(2)

            # NOTE: Do NOT reload SSL context yet - wait until after all nodes start
            # Reloading now causes TLS errors when primary tries to connect to secondaries
        except Exception as e:
            write_chunk(handler.wfile, f"End: Certificate generation failed: {str(e)}\n")
            end_stream(handler=handler)
            stream_ended = True
            return {"detail": f"Certificate generation failed: {str(e)}"}, 500

        # ============================================================
        # PHASE 3: Copy certificates to shared NFS storage (HA only)
        # ============================================================
        if is_ha_enabled:
            write_chunk(handler.wfile, "Copying certificates to shared storage...\n")
            ha_nfs_dir = AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY", "/opt/shared/data")
            success, error_msg = copy_and_set_permissions_ha(handler, True, ha_nfs_dir, is_https_ui, renew_ca, renew_ui)
            if not success:
                write_chunk(handler.wfile, f"End: Failed to copy to shared storage: {error_msg}\n")
                end_stream(handler=handler)
                stream_ended = True
                return {"detail": error_msg}, 500
            write_chunk(handler.wfile, "Certificates copied to shared storage\n")

        # ============================================================
        # PHASE 4: Sync certificates to secondary nodes (HA only)
        # ============================================================
        if is_ha_enabled and secondary_nodes:
            write_chunk(handler.wfile, f"Syncing certificates to {len(secondary_nodes)} secondary node(s)...\n")
            sync_failed_nodes = []
            for node_ip in secondary_nodes:
                try:
                    for response_chunk in check_management_server(
                        handler=handler,
                        endpoint="/api/management/sync-certs",
                        node_ip=node_ip,
                        method="POST",
                        protocol=protocol,
                        should_stream=True,
                        payload={"renew_ca": renew_ca, "renew_ui": renew_ui},
                    ):
                        if response_chunk.strip().upper().startswith("END:"):
                            raise RuntimeError(response_chunk)
                        write_chunk(handler.wfile, response_chunk, node_ip=node_ip)
                except Exception as e:
                    sync_failed_nodes.append((node_ip, str(e)))
                    write_chunk(handler.wfile, f"Error: Failed to sync to {node_ip}: {str(e)}\n")

            if sync_failed_nodes:
                write_chunk(handler.wfile, f"End: Failed to sync certificates to {len(sync_failed_nodes)} node(s)\n")
                end_stream(handler=handler)
                stream_ended = True
                return {"detail": f"Failed to sync {len(sync_failed_nodes)} node(s)"}, 500

        # ============================================================
        # PHASE 5: Restart management server to load new certs (if needed)
        # ============================================================
        # Note: Management server will auto-reload certs via SNI callback

        # ============================================================
        # PHASE 6: Signal management servers to hot-reload new certificates
        # CRITICAL: Do this BEFORE starting any nodes to avoid TLS errors
        # ============================================================
        write_chunk(handler.wfile, "Triggering SSL hot-reload on all management servers...\n")

        # Reload all nodes (primary + secondary)
        all_nodes = [primary_node_ip] + secondary_nodes if is_ha_enabled else [primary_node_ip]
        for node_ip in all_nodes:
            try:
                # Use direct call for local node, API for remote nodes
                if node_ip == utils.NODE_IP:
                    tls_version = get_tls_version()
                    force_ssl_context_reload(tls_version=tls_version)
                    write_chunk(handler.wfile, "SSL context reloaded on local node\n")
                else:
                    for response_chunk in check_management_server(
                        handler=handler,
                        endpoint="/api/management/reload-certs",
                        node_ip=node_ip,
                        method="POST",
                        protocol=protocol,
                        should_stream=False,
                    ):
                        pass
                    write_chunk(handler.wfile, f"SSL context reloaded on {node_ip}\n")
            except Exception as e:
                write_chunk(handler.wfile, f"Warning: SSL hot-reload failed on {node_ip}: {str(e)}\n")

        # Wait for SSL context to be fully reloaded and stabilized
        time.sleep(3)

        # ============================================================
        # PHASE 7: Start ONLY nodes that were previously running
        # ============================================================
        if nodes_to_restart:
            write_chunk(handler.wfile, f"Starting {len(nodes_to_restart)} node(s) that were running...\n")

            # CRITICAL: Start ALL secondary nodes FIRST (in parallel), then primary
            # This prevents MongoDB replica set connection errors
            if is_ha_enabled and secondary_nodes:
                # Start all secondary nodes first
                for node_ip in secondary_nodes:
                    if node_ip not in nodes_to_restart:
                        continue

                    write_chunk(handler.wfile, f"Starting CE on secondary node {node_ip}...\n")
                    try:
                        start_failed = False
                        for response_chunk in check_management_server(
                            handler=handler,
                            endpoint="/api/management/start-ce",
                            node_ip=node_ip,
                            method="POST",
                            protocol=protocol,
                            should_stream=True,
                            payload={"node_ip": node_ip},
                        ):
                            if response_chunk.strip().upper().startswith("END:"):
                                start_failed = True
                            write_chunk(handler.wfile, response_chunk, node_ip=node_ip)

                        if start_failed:
                            write_chunk(handler.wfile, f"Warning: Failed to start secondary {node_ip}\n")
                    except Exception as e:
                        write_chunk(handler.wfile, f"Warning: Error starting secondary {node_ip}: {str(e)}\n")

                # Wait for secondary nodes to be ready
                write_chunk(handler.wfile, "Waiting for secondary nodes to be ready...\n")
                time.sleep(15)

            # Now start primary node (if it was running)
            if primary_node_ip in nodes_to_restart:
                write_chunk(handler.wfile, f"Starting CE on primary node {primary_node_ip}...\n")

                try:
                    start_failed = False
                    for response_chunk in check_management_server(
                        handler=handler,
                        endpoint="/api/management/start-ce",
                        node_ip=primary_node_ip,
                        method="POST",
                        protocol=protocol,
                        should_stream=True,
                        payload={"node_ip": primary_node_ip},
                    ):
                        if response_chunk.strip().upper().startswith("END:"):
                            start_failed = True
                        write_chunk(handler.wfile, response_chunk, node_ip=primary_node_ip)

                    if start_failed:
                        write_chunk(handler.wfile, f"End: Failed to start primary {primary_node_ip}\n")
                        end_stream(handler=handler)
                        stream_ended = True
                        return {"detail": f"Failed to start {primary_node_ip}"}, 500
                except Exception as e:
                    write_chunk(handler.wfile, f"End: Failed to start primary {primary_node_ip}: {str(e)}\n")
                    end_stream(handler=handler)
                    stream_ended = True
                    return {"detail": f"Failed to start {primary_node_ip}: {str(e)}"}, 500

            # Wait for services to fully start
            write_chunk(handler.wfile, "Waiting for services to start...\n")
            time.sleep(20)
        else:
            write_chunk(handler.wfile, "All nodes were stopped, keeping them stopped\n")

        write_chunk(handler.wfile, "Certificate renewal completed successfully\n")
        end_stream(handler=handler)
        stream_ended = True

        return {"detail": "Certificate renewal completed"}, 200

    except Exception as e:
        logger.error(f"Certificate renewal error: {e}", extra={"node": utils.NODE_IP})
        write_chunk(handler.wfile, f"End: {str(e)}\n")
        if not stream_ended:
            end_stream(handler=handler)
        return {"detail": str(e)}, 500
    finally:
        if not stream_ended:
            end_stream(handler=handler)


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
        logger.warning(f"Config file '{file_path}' does not exist.", extra={"node": utils.NODE_IP})
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
        return {"detail": f"Error encountered while updating config file. Error: {str(e)}."}, 500
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
        return {"detail": f"Error encountered while reading config file. Error: {str(e)}."}, 500


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
        write_chunk(handler.wfile, "End: Please provide a valid shared directory path\n")
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
        return {"detail": "Please provide a valid shared directory path and current node ip."}, 400

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

    response = verify_start_create_volume(handler=handler, current_node_ip=current_node_ip)
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
    jwt_secret = get_decrypted_jwt_secret()
    response = update_config_file(
        handler=handler,
        keys_to_update={
            "HA_ENABLED": True,
            "HA_CURRENT_NODE": current_node_ip,
            "HA_PRIMARY_NODE_IP": current_node_ip,
            "HA_NFS_DATA_DIRECTORY": f"{shared_base_directory}/data",
            "HA_IP_LIST": f"{current_node_ip}",
            "JWT_SECRET": jwt_secret,
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

    if AVAILABLE_INPUTS.get("HA_CURRENT_NODE") or AVAILABLE_INPUTS.get("LOCATION", "") != ".env.keys":
        try:
            location = AVAILABLE_INPUTS["LOCATION"]
            directory = os.path.dirname(location.rstrip("/"))
            env_path = os.path.join(directory, ".env")

            get_all_existed_env_variable(location=env_path, override=True)
        except Exception as e:
            error_msg = f"Error encountered while fetching environment details. Error: {e}"
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
    handler=None,
    endpoint=None,
    method=None,
    protocol="https",
    should_stream=False,
    should_stream_binary=False,
    payload=None,
    params=None,
    auth_header=None,
):
    """
    Check the management server.

    Args:
        node_ip (str): The IP address of the host machine.
        handler (Handler, optional): The handler object. Defaults to None.
        endpoint (str): The endpoint to hit.
        method (str): The HTTP method to use.
        protocol (str): The protocol to use. Defaults to "https".
        should_stream (bool): A boolean indicating whether to stream text response.
        should_stream_binary (bool): A boolean indicating whether to stream binary response.
        payload (str): The payload to send with the request.
        params (dict): Query parameters to append to the endpoint.
        auth_header (str, optional): Authorization header string for background threads. Defaults to None.

    Returns:
        Response: The response object (yields text lines, binary chunks, or JSON).
    """
    ce_management_port = int(AVAILABLE_INPUTS.get("CE_MANAGEMENT_PORT", 8000))
    conn = None

    if protocol == "http" or protocol == "https":  # management server is always https.
        server_cert, server_key, client_ca = get_certs_locations()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(
            certfile=server_cert,
            keyfile=server_key,
        )
        if client_ca and os.path.exists(client_ca):
            context.load_verify_locations(cafile=client_ca)
        else:
            logger.warning("Common CA cert not found.")
        conn = http.client.HTTPSConnection(node_ip, ce_management_port, context=context)
    else:
        raise Exception("Invalid protocol")

    # Handle authorization from handler OR auth_header
    headers = {}
    if handler and handler.headers.get("Authorization"):
        # Regular request - extract from handler
        new_token = create_token(handler.headers.get("Authorization"))
        if not new_token:
            logger.warning("Generated token is invalid, using the token from request.")
            headers["Authorization"] = handler.headers.get("Authorization")
        else:
            headers["Authorization"] = f"Bearer {new_token}"
    elif auth_header:
        # Background thread - use provided auth_header
        new_token = create_token(auth_header)
        if not new_token:
            logger.warning("Generated token is invalid, using the provided token.")
            headers["Authorization"] = auth_header
        else:
            headers["Authorization"] = f"Bearer {new_token}"

    try:
        if payload:
            payload = json.dumps(payload)
        if params and isinstance(params, dict):
            endpoint += f"?{urlencode(params)}"

        conn.request(method=method, url=endpoint, headers=headers, body=payload)
        res = conn.getresponse()
        handle_http_errors(res=res)

        # Binary streaming mode (for file downloads)
        if should_stream_binary:
            # First yield the response object so caller can check headers/status
            yield res
            while True:
                chunk = res.read(8192)  # Read 8KB binary chunks
                if not chunk:
                    break
                yield chunk
        # Text streaming mode (for log messages)
        elif should_stream:
            while True:
                response = res.readline().decode()
                if not response:
                    break
                yield response
        # JSON response mode
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
        enhanced_error = ssl.CertificateError(
            f"{e}. Please ensure configured CA key is same as Primary Node's CA key before executing CE Setup."
        )
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
    AVAILABLE_INPUTS["UI_PROTOCOL"] = AVAILABLE_INPUTS.get("UI_PROTOCOL", "http").lower().strip()
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
        return {"detail": f"Issue connecting to Management Server at {node_ip}. {str(e)}"}, 400

    AVAILABLE_INPUTS["HA_ENABLED"] = True
    AVAILABLE_INPUTS["HA_CURRENT_NODE"] = node_ip
    AVAILABLE_INPUTS["HA_IP_LIST"] = update_ha_ip_list(AVAILABLE_INPUTS["HA_IP_LIST"], ip_to_add=node_ip)

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
        return {"detail": f"Error encountered while updating the Cloud Exchange config file on new node. {str(e)}"}, 500

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
            (f"End: Error encountered while validating prerequisites for new node. Error: {str(e)}\n"),
        )
        end_stream(handler=handler)
        return {"detail": f"Error encountered while validating prerequisites for new node. {str(e)}"}, 500

    # install GlusterFS on new node
    shared_base_directory_path = "/".join(
        (AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY").strip().rstrip("/").split("/"))[:-1]
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
        return {"detail": f"Error encountered while installing GlusterFS on new node. {str(e)}"}, 500

    # peer probe from current
    write_chunk(handler.wfile, "Info: Peering with new node.\n")
    command = f"{SUDO_PREFIX} gluster peer probe {node_ip}"
    command = command.strip().split(" ")
    response = execute_command_with_logging(command, handler, message="peering with new node")
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
            for message in retirable_execute_command(command, input_data="y\n", max_retries=3, max_delay=5):
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
            return {"detail": "Error encountered while adding new brick to CloudExchange volume."}, 500
    try:
        write_chunk(handler.wfile, "Info: Triggering full heal on CloudExchange volume.\n")
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
        return {"detail": "Error encountered while triggering heal operation on CloudExchange volume."}, 500

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
        return {"detail": f"Error encountered while mounting GlusterFS volume on new node. {str(e)}"}, 500

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
        return {"detail": f"Error encountered while running setup on new node. {str(e)}"}, 500

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
            return {"detail": f"Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}"}, 500

    write_chunk(handler.wfile, f"Info: Stopping Cloud Exchange Primary Node {primary_node}.\n")
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
        return {"detail": f"Error encountered while stopping Cloud Exchange on Node {primary_node}. {str(e)}"}, 500

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
        return {"detail": f"Error encountered while starting Cloud Exchange on Node {primary_node}. {str(e)}"}, 500

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
        return {"detail": f"Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}"}, 500

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
        return {"detail": f"Error encountered while running start on new node. {str(e)}"}, 500

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
        return {"detail": f"Error encountered while running restarting Cloud Exchange on node: {ip}. {str(e)}"}, 500

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
    AVAILABLE_INPUTS["UI_PROTOCOL"] = AVAILABLE_INPUTS.get("UI_PROTOCOL", "http").lower().strip()
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
        write_chunk(handler.wfile, f"Error: Issue connecting to Management Server. {str(e)}\n")
        end_stream(handler=handler)
        return {"detail": f"Issue connecting to Management Server on node {node_ip}. {str(e)}"}, 400

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
        return {"detail": f"Error encountered while stopping Cloud Exchange on node: {node_ip}. {str(e)}"}, 500

    # update_config
    AVAILABLE_INPUTS["HA_IP_LIST"] = update_ha_ip_list(AVAILABLE_INPUTS.get("HA_IP_LIST", ""), ip_to_remove=node_ip)
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
        return {"detail": f"Error encountered while updating env file on node {node_ip}. {str(e)}"}, 500

    # remove brick from GlusterFS volume
    write_chunk(handler.wfile, "Info: Removing brick from GlusterFS volume.\n")
    replica_nodes = len(AVAILABLE_INPUTS.get("HA_IP_LIST", "").rstrip(",").split(","))
    shared_dir_base_path = "/".join((AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY").strip().rstrip("/").split("/"))[:-1])
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
        return {"detail": "Error encountered while removing brick from GlusterFS volume."}, 500
    write_chunk(handler.wfile, "Info: Successfully removed brick from GlusterFS volume.\n")

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
        return {"detail": f"Error encountered while un-mounting CloudExchange volume on node: {node_ip}. {str(e)}"}, 500

    # detach-node
    write_chunk(handler.wfile, f"Info: Detaching node {node_ip} from GlusterFS.\n")
    command = f"{SUDO_PREFIX} gluster peer detach {node_ip}"
    command = command.strip().split(" ")
    response = execute_command_with_logging(command, handler, input_data="y\n", message="detaching node from GlusterFS")
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
            return {"detail": f"Error encountered while stopping Cloud Exchange on Node {ip}. {str(e)}"}, 500

    write_chunk(handler.wfile, f"Info: Stopping Cloud Exchange Primary Node {primary_node}.\n")
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
        return {"detail": f"Error encountered while stopping Cloud Exchange on Node {primary_node}. {str(e)}"}, 500

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
        return {"detail": f"Error encountered while starting Cloud Exchange on Node {primary_node}. {str(e)}"}, 500

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
        return {"detail": f"Error encountered while starting Cloud Exchange on Node {ip}. {str(e)}"}, 500

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
        (AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY").strip().rstrip("/").split("/"))[:-1]
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
        return {"detail": "Error encountered while copying plugins, repos and custom plugins to data directory."}, 500

    # Move the custom certs to data directory.
    write_chunk(handler.wfile, "Info: Moving custom certs and ssl certs to data directory.\n")
    command = (
        f"{SUDO_PREFIX} cp -r {shared_base_directory}/data/config/ca_certs "
        f"{shared_base_directory}/data/config/ssl_certs ./data/"
    )
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
        return {"detail": "Error encountered while copying env files from shared directory."}, 500
    write_chunk(handler.wfile, "Info: Copied env files from shared directory.\n")

    # Update Cloud Exchange config.
    try:
        write_chunk(handler.wfile, "Info: Updating Cloud Exchange env file.\n")
        jwt_secret = get_decrypted_jwt_secret()
        data = {
            "HA_ENABLED": False,
            "HA_IP_LIST": "",
            "HA_CURRENT_NODE": "",
            "HA_NFS_DATA_DIRECTORY": "",
            "JWT_SECRET": jwt_secret,
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
        return {"detail": "Error encountered while updating Cloud Exchange config."}, 500

    write_chunk(handler.wfile, "Info: Setting up Cloud Exchange as Standalone deployment.")
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


def _run_local_diagnose():
    """
    Run the ./diagnose script locally and return the path to the generated zip file.

    This function executes the diagnose bash script which collects system information,
    container logs, and CE platform details, then packages them into a zip file.

    Uses the common execute_command utility for consistent command execution.
    The diagnose script outputs the path to the generated zip file as its last line.
    The zip file is typically created in /opt/cloudexchange/ directory.

    Returns:
        tuple: (success: bool, result: str)
            - On success: (True, path_to_zip_file)
            - On failure: (False, error_message)
    """
    command = f"{SUDO_PREFIX} ./diagnose".strip()
    diagnose_file = None
    return_code = 0
    stderr_output = []

    logger.info(f"Running diagnose command: {command}", extra={"node": utils.NODE_IP})

    try:
        # Use the common execute_command utility for consistent command execution
        for message in execute_command(command, shell=True):
            msg_type = message.get("type", "")
            msg_content = message.get("message", "").strip()

            if msg_type == "stdout":
                # Check if this line contains the zip file path
                if msg_content.endswith(".zip"):
                    diagnose_file = msg_content
                    logger.info("Found diagnose zip path: {}".format(diagnose_file), extra={"node": utils.NODE_IP})
            elif msg_type == "stderr":
                if msg_content:
                    stderr_output.append(msg_content)
            elif msg_type == "returncode":
                return_code = message.get("code", 0)

        logger.info(
            f"Diagnose script completed with return code: {return_code}",
            extra={"node": utils.NODE_IP},
        )

        if return_code != 0:
            error_detail = "; ".join(stderr_output) if stderr_output else "Unknown error"
            return (
                False,
                f"Diagnose script failed with return code {return_code}: {error_detail}",
            )

        if not diagnose_file or not os.path.exists(diagnose_file):
            return (
                False,
                "Diagnose completed but zip file path not captured from script output",
            )

        return True, diagnose_file

    except Exception as e:
        logger.error(f"Error running diagnose: {str(e)}", extra={"node": utils.NODE_IP})
        return False, f"Error running diagnose: {str(e)}"


def _collect_remote_diagnose(node_ip, auth_header):
    """
    Collect diagnose zip from a remote node in the HA cluster.

    This function makes an HTTPS request to the remote node's /run-diagnose-node endpoint,
    which triggers the diagnose script on that node and returns the zip file directly.
    The received zip file is saved to the shared NFS directory.

    Args:
        node_ip: IP address of the remote node to collect diagnose from
        auth_header: Authorization header value from the original request

    Returns:
        tuple: (success: bool, result: str, node_ip: str)
            - On success: (True, path_to_saved_zip, node_ip)
            - On failure: (False, error_message, node_ip)
    """
    try:
        # Prepare the directory to store the downloaded zip file
        shared_dir = AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY", "/opt/shared/data")
        diagnose_dir = os.path.join(shared_dir, "diagnose_files")
        os.makedirs(diagnose_dir, exist_ok=True)

        # Generate unique filename for this node's diagnose zip
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        node_filename = f"node_{node_ip.replace('.', '_')}_{timestamp}.zip"
        file_path = os.path.join(diagnose_dir, node_filename)

        # Use check_management_server with binary streaming mode
        stream = check_management_server(
            node_ip=node_ip,
            handler=None,
            auth_header=auth_header,
            endpoint="/api/management/run-diagnose-node",
            method="POST",
            protocol="https",
            should_stream_binary=True,
        )

        # First item yielded is the response object
        res = next(stream)

        # Check if response is a JSON error (status 500) or binary zip (status 200)
        status_code = res.code
        content_type = res.getheader("Content-Type", "")

        if status_code != 200:
            # Read error response as JSON
            error_data = res.read().decode()
            try:
                error_json = json.loads(error_data)
                error_msg = error_json.get("detail", error_data)
            except (JSONDecodeError, TypeError):
                error_msg = error_data
            logger.error(f"Remote diagnose failed on {node_ip}: {error_msg}", extra={"node": utils.NODE_IP})
            return False, f"Remote node returned error: {error_msg}", node_ip

        if "application/zip" not in content_type:
            # Unexpected content type
            logger.error(f"Unexpected Content-Type from {node_ip}: {content_type}", extra={"node": utils.NODE_IP})
            return False, f"Unexpected response type: {content_type}", node_ip

        # Stream the binary zip file
        with open(file_path, "wb") as f:
            for chunk in stream:
                f.write(chunk)

        # Verify the downloaded file is valid
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            logger.info(f"Successfully collected diagnose from {node_ip}: {file_path}", extra={"node": utils.NODE_IP})
            return True, file_path, node_ip
        else:
            return False, "Downloaded file is empty or missing", node_ip

    except Exception as e:
        logger.error(f"Error collecting diagnose from {node_ip}: {str(e)}", extra={"node": utils.NODE_IP})
        return False, str(e), node_ip


def _merge_diagnose_zips(zip_files, output_path):
    """
    Merge multiple diagnose zip files into a single cluster zip.

    Args:
        zip_files: List of tuples (node_ip, zip_file_path)
        output_path: Path for the merged zip file

    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    try:
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as merged_zip:
            for node_ip, zip_path in zip_files:
                if not os.path.exists(zip_path):
                    continue

                # Create a folder for each node in the merged zip
                node_folder = f"node_{node_ip.replace('.', '_')}"

                with zipfile.ZipFile(zip_path, "r") as node_zip:
                    for item in node_zip.namelist():
                        # Read file content from source zip
                        content = node_zip.read(item)
                        # Write to merged zip under node-specific folder
                        merged_zip.writestr(f"{node_folder}/{item}", content)

        return True, None
    except Exception as e:
        return False, str(e)


def _cleanup_diagnose_files(file_paths):
    """
    Clean up temporary diagnose files.

    Args:
        file_paths: List of file paths to remove
    """
    for path in file_paths:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except Exception as e:
            logger.warning(f"Failed to cleanup file {path}: {str(e)}", extra={"node": utils.NODE_IP})


def _pre_check_ha_nodes_for_diagnose(auth_header, ha_ip_list, current_node_ip):
    """
    Pre-check all HA nodes before starting diagnose collection.

    This function checks the health of all nodes in the HA cluster and logs
    warnings for any nodes that have issues. Warnings are logged to backend only.

    Uses direct HTTPS connections for remote node communication since this
    runs in a background thread.

    Args:
        auth_header: Authorization header for remote calls
        ha_ip_list: Comma-separated list of HA node IPs
        current_node_ip: IP of the current node

    Returns:
        dict: node_status mapping node_ip to status dict
    """
    node_status = {}
    all_node_ips = [ip.strip() for ip in ha_ip_list.split(",") if ip.strip()]

    for node_ip in all_node_ips:
        if node_ip == current_node_ip:
            # Local node - check CE status directly
            fetch_container_info()
            local_ce_running = utils.is_ui_running and utils.is_rabbitmq_running and utils.is_mongodb_running
            node_status[node_ip] = {
                "management_server": "running",
                "ce_status": "running" if local_ce_running else "stopped",
                "is_local": True,
            }
            if not local_ce_running:
                logger.warning(
                    f"Diagnose: Local node ({node_ip}) CE containers are stopped. "
                    f"Some container logs may be missing in diagnose output.",
                    extra={"node": utils.NODE_IP},
                )
            continue

        # Check remote node management server health
        try:
            for response in check_management_server(
                node_ip=node_ip,
                handler=None,
                auth_header=auth_header,
                endpoint="/api/management/node-details",
                method="GET",
                protocol="https",
                should_stream=False,
            ):
                if isinstance(response, tuple) and len(response) >= 2:
                    is_reachable = response[1] == 200
                    error_msg = None if is_reachable else f"Status {response[1]}"
                elif isinstance(response, dict):
                    is_reachable = True
                    error_msg = None
                break
        except Exception as e:
            is_reachable = False
            error_msg = str(e)

        if not is_reachable:
            node_status[node_ip] = {
                "management_server": "unreachable",
                "ce_status": "unknown",
                "is_local": False,
                "error": error_msg,
            }
            # Log warning to backend only
            logger.warning(
                f"Diagnose: Node {node_ip} management server is not reachable. "
                f"Error: {error_msg}. Diagnose logs for this node will be missing. "
                f"Please start the management server on this node for complete HA diagnostics.",
                extra={"node": utils.NODE_IP},
            )
            continue

        # Management server is reachable; initialize node status once
        node_status[node_ip] = {"management_server": "running", "ce_status": "unknown", "is_local": False}

        # Now check CE status only and update ce_status / error
        try:
            for response in check_management_server(
                node_ip=node_ip,
                handler=None,
                auth_header=auth_header,
                endpoint="/api/management/ce-status",
                method="GET",
                protocol="https",
                should_stream=False,
            ):
                if isinstance(response, tuple) and len(response) >= 2:
                    if response[1] == 200 and isinstance(response[0], dict):
                        ce_running = response[0].get("is_running", False)
                        ce_error = None
                    else:
                        ce_running = False
                        ce_error = f"HTTP {response[1]}"
                elif isinstance(response, dict):
                    ce_running = response.get("is_running", False)
                    ce_error = None
                break
        except Exception as e:
            ce_running = False
            ce_error = str(e)

        if ce_running:
            node_status[node_ip]["ce_status"] = "running"
            logger.info(
                f"Diagnose: Node {node_ip} management server and CE containers are running.",
                extra={"node": utils.NODE_IP},
            )
        else:
            node_status[node_ip]["ce_status"] = "stopped"
            node_status[node_ip]["error"] = ce_error
            # Log warning to backend only
            logger.warning(
                f"Diagnose: Node {node_ip} CE containers are stopped. "
                f"Some CE logs may be missing or incomplete for this node. "
                f"Consider starting CE containers on this node before collecting diagnostics.",
                extra={"node": utils.NODE_IP},
            )

    # Log summary
    reachable_nodes = [ip for ip, st in node_status.items() if st.get("management_server") == "running"]
    unreachable_nodes = [ip for ip, st in node_status.items() if st.get("management_server") == "unreachable"]

    if unreachable_nodes:
        logger.warning(
            f"Diagnose: {len(unreachable_nodes)} node(s) have unreachable management servers: "
            f"{', '.join(unreachable_nodes)}. Diagnose will proceed with {len(reachable_nodes)} reachable node(s).",
            extra={"node": utils.NODE_IP},
        )
    else:
        logger.info(
            f"Diagnose: All {len(reachable_nodes)} node(s) have reachable management servers.",
            extra={"node": utils.NODE_IP},
        )

    return node_status


def _send_json_error_response(handler, error_message, status_code):
    """
    Send a JSON error response to the client.

    This helper function formats and sends an error response with the appropriate
    HTTP status code and JSON content type.

    Args:
        handler: HTTP request handler object
        error_message: Error message to include in the response
        status_code: HTTP status code (e.g., 400, 500)

    Returns:
        tuple: (response_dict, status_code) for consistency with other handlers
    """
    response = json.dumps({"detail": error_message}).encode()
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(response)))
    handler.end_headers()
    handler.wfile.write(response)
    handler.wfile.flush()
    return {"detail": error_message}, status_code


def _send_zip_file_download(handler, zip_file_path, filename, files_to_cleanup):
    """
    Send a zip file as direct binary HTTP response for download.

    This function sends the zip file with appropriate headers for browser download.
    The file is streamed in chunks to handle large files efficiently.

    Args:
        handler: HTTP request handler object
        zip_file_path: Absolute path to the zip file to send
        filename: Filename to use in Content-Disposition header (download name)
        files_to_cleanup: List of file paths to delete after successful send

    Returns:
        None - Response is sent directly, caller should return this None value
    """
    try:
        # Verify the zip file exists before attempting to send
        if not os.path.exists(zip_file_path):
            logger.error(f"Zip file not found: {zip_file_path}", extra={"node": utils.NODE_IP})
            return _send_json_error_response(handler, "Zip file not found", 500)

        # Get file size for Content-Length header
        file_size = os.path.getsize(zip_file_path)

        # Send HTTP response headers for binary file download
        handler.send_response(200)
        handler.send_header("Content-Type", "application/zip")
        handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        handler.send_header("Content-Length", str(file_size))
        handler.send_header("Connection", "close")  # Prevent keep-alive issues
        handler.end_headers()

        # Stream the file content in 8KB chunks
        with open(zip_file_path, "rb") as f:
            while True:
                chunk = f.read(8192)  # 8KB chunks for efficient streaming
                if not chunk:
                    break
                handler.wfile.write(chunk)

        # Cleanup temporary files after successful send
        _cleanup_diagnose_files(files_to_cleanup)

        logger.info(f"Diagnose file sent successfully: {filename} ({file_size} bytes)", extra={"node": utils.NODE_IP})

        write_chunk(handler.wfile, "End: Diagnose file sent successfully.\n")

        # Return None to signal that response was already sent
        # This prevents SimpleAPIServer from trying to send headers again
        return None, 200

    except Exception as e:
        logger.error(f"Error sending zip file: {str(e)}", extra={"node": utils.NODE_IP})
        _cleanup_diagnose_files(files_to_cleanup)
        return _send_json_error_response(handler, f"Error sending file: {str(e)}", 500)


def _update_diagnose_job(updates):
    """Thread-safe helper to update CURRENT_DIAGNOSE_JOB and persist to disk."""
    global CURRENT_DIAGNOSE_JOB
    with _diagnose_job_lock:
        if CURRENT_DIAGNOSE_JOB:
            CURRENT_DIAGNOSE_JOB.update(updates)
            # Persist updates to disk so other HA nodes can see status changes
            output_dir = _get_diagnose_output_dir()
            if os.path.exists(output_dir):
                _save_diagnose_job_metadata(CURRENT_DIAGNOSE_JOB, output_dir)


def _run_diagnose_worker(job_id, auth_header, is_ha_mode, ha_ip_list):
    """
    Background worker for diagnose. Updates CURRENT_DIAGNOSE_JOB.

    This worker performs health checks on HA nodes before collecting diagnostics
    and logs warnings to backend for unreachable management servers or stopped
    CE containers.

    Args:
        job_id: Unique job identifier
        auth_header: Authorization header for remote calls
        is_ha_mode: Whether running in HA mode
        ha_ip_list: Comma-separated list of HA node IPs
    """
    global CURRENT_DIAGNOSE_JOB
    files_to_cleanup = []
    timestamp = datetime.now().strftime("%a_%d_%b_%Y_%H_%M_%S")
    output_dir = _get_diagnose_output_dir()

    try:
        os.makedirs(output_dir, exist_ok=True)

        if not is_ha_mode:
            # Single node mode - check CE status and run local diagnose
            _update_diagnose_job({"message": "Checking CE container status..."})

            # Check local CE status first and log warning if stopped
            fetch_container_info()
            ce_running = utils.is_ui_running and utils.is_rabbitmq_running and utils.is_mongodb_running
            if not ce_running:
                logger.warning(
                    f"Diagnose: CE containers are stopped on this node ({utils.NODE_IP}). "
                    f"Some CE container logs may be missing or incomplete in diagnose output. "
                    f"Consider starting CE containers before collecting diagnostics for complete logs.",
                    extra={"node": utils.NODE_IP},
                )
            else:
                logger.info(
                    f"Diagnose: CE containers are running on this node ({utils.NODE_IP}).",
                    extra={"node": utils.NODE_IP},
                )

            _update_diagnose_job({"message": "Running diagnose script..."})
            success, result = _run_local_diagnose()
            completion_msg = ""
            errors = []
            output_path = None
            output_filename = None

            if not success:
                completion_msg += f"Diagnose failed: {result}"
                errors.append(result)
            else:
                # Filename format: diagnose_{job_id}_{timestamp}.zip
                output_filename = f"diagnose_{job_id}_{timestamp}.zip"
                output_path = os.path.join(output_dir, output_filename)
                shutil.copy2(result, output_path)
                files_to_cleanup.append(result)
                completion_msg = "Diagnose completed"
            if not ce_running:
                completion_msg += " (CE containers were stopped - some logs may be missing)"

            job_update = {
                "status": "completed" if success else "failed",
                "message": completion_msg,
                "file_path": output_path,
                "file_name": output_filename,
                "ce_status": "running" if ce_running else "stopped",
                "errors": errors,
            }
            _update_diagnose_job(job_update)
            # Persist job metadata to file for recovery after restart
            with _diagnose_job_lock:
                if CURRENT_DIAGNOSE_JOB:
                    _save_diagnose_job_metadata(CURRENT_DIAGNOSE_JOB, output_dir)
        else:
            # HA mode - check node health before collecting
            current_node_ip = AVAILABLE_INPUTS.get("HA_CURRENT_NODE", "").strip() or (
                utils.NODE_IP.strip() if utils.NODE_IP else ""
            )
            all_node_ips = [ip.strip() for ip in ha_ip_list.split(",") if ip.strip()]
            remote_node_ips = [ip for ip in all_node_ips if ip != current_node_ip]
            total_nodes = len(all_node_ips)

            # Pre-check all nodes for health status (logs warnings to backend)
            _update_diagnose_job({"message": f"HA mode: Checking health of {total_nodes} nodes..."})
            node_status = _pre_check_ha_nodes_for_diagnose(auth_header, ha_ip_list, current_node_ip)

            # Identify which nodes to skip based on pre-check
            unreachable_nodes = [
                ip for ip, status in node_status.items() if status.get("management_server") == "unreachable"
            ]

            # Identify nodes with stopped CE containers
            stopped_ce_nodes = [ip for ip, status in node_status.items() if status.get("ce_status") == "stopped"]

            _update_diagnose_job({"message": f"HA mode: collecting from {total_nodes} nodes"})
            collected_zips = []
            errors = []

            # Collect from local node first
            _update_diagnose_job({"message": f"Running on local node ({current_node_ip})..."})
            success, result = _run_local_diagnose()
            if success:
                collected_zips.append((current_node_ip, result))
                files_to_cleanup.append(result)
            else:
                errors.append(f"Local ({current_node_ip}): {result}")
                logger.error(
                    f"Diagnose: Local node ({current_node_ip}) diagnose script failed: {result}",
                    extra={"node": utils.NODE_IP},
                )

            # Collect from remote nodes
            for node_ip in remote_node_ips:
                # Skip nodes that were identified as unreachable in pre-check
                if node_ip in unreachable_nodes:
                    errors.append(f"{node_ip}: Management server unreachable (skipped)")
                    continue

                _update_diagnose_job({"message": f"Collecting from {node_ip}..."})
                success, result, _ = _collect_remote_diagnose(node_ip, auth_header)

                if success:
                    collected_zips.append((node_ip, result))
                    files_to_cleanup.append(result)
                    # Log success message, note if CE was stopped
                    if node_ip in stopped_ce_nodes:
                        logger.info(
                            f"Diagnose: Successfully collected from {node_ip}. "
                            f"Note: CE containers were stopped, some CE logs may be missing.",
                            extra={"node": utils.NODE_IP},
                        )
                else:
                    errors.append(f"{node_ip}: {result}")
                    # Log specific error based on error type to backend
                    if "Connection refused" in result or "not running" in result.lower():
                        logger.warning(
                            f"Diagnose: Node {node_ip} management server stopped during collection. "
                            f"Diagnose logs missing for this node. Start management server and retry.",
                            extra={"node": utils.NODE_IP},
                        )
                    elif "timeout" in result.lower():
                        logger.warning(
                            f"Diagnose: Node {node_ip} connection timed out during collection. "
                            f"The node may be overloaded or network issues exist.",
                            extra={"node": utils.NODE_IP},
                        )
                    else:
                        logger.warning(
                            f"Diagnose: Node {node_ip} failed to collect diagnose: {result}",
                            extra={"node": utils.NODE_IP},
                        )

            # Check if we collected anything
            if not collected_zips:
                raise Exception("No diagnose collected from any node. Errors: " + "; ".join(errors))

            _update_diagnose_job({"message": f"Merging {len(collected_zips)} node files..."})

            # Filename format: cluster_{job_id}_{timestamp}.zip
            merged_zip_name = f"cluster_{job_id}_{timestamp}.zip"
            merged_zip_path = os.path.join(output_dir, merged_zip_name)

            success, merge_error = _merge_diagnose_zips(collected_zips, merged_zip_path)
            if not success:
                raise Exception(f"Merge failed: {merge_error}")

            # Build completion message with summary
            collected_count = len(collected_zips)
            skipped_count = len(unreachable_nodes)
            error_count = len(errors)

            completion_msg = f"Completed ({collected_count}/{total_nodes} nodes)"
            if skipped_count > 0:
                completion_msg += f", {skipped_count} unreachable"
            if error_count > skipped_count:
                completion_msg += f", {error_count - skipped_count} failed"

            job_update = {
                "status": "completed",
                "message": completion_msg,
                "file_path": merged_zip_path,
                "file_name": merged_zip_name,
                "node_summary": {
                    "total": total_nodes,
                    "collected": collected_count,
                    "unreachable": skipped_count,
                    "errors": errors,
                },
            }
            _update_diagnose_job(job_update)
            # Persist job metadata to file for recovery after restart
            with _diagnose_job_lock:
                if CURRENT_DIAGNOSE_JOB:
                    _save_diagnose_job_metadata(CURRENT_DIAGNOSE_JOB, output_dir)

            # Log summary to backend
            if unreachable_nodes:
                logger.warning(
                    f"Diagnose completed: {len(unreachable_nodes)} node(s) had "
                    f"unreachable management servers: {', '.join(unreachable_nodes)}. "
                    f"Start management servers on these nodes for complete diagnostics.",
                    extra={"node": utils.NODE_IP},
                )
            if stopped_ce_nodes:
                logger.warning(
                    f"Diagnose completed: {len(stopped_ce_nodes)} node(s) had stopped CE containers: "
                    f"{', '.join(stopped_ce_nodes)}. Some CE logs may be missing for these nodes.",
                    extra={"node": utils.NODE_IP},
                )
            if collected_count == total_nodes:
                logger.info(
                    f"Diagnose completed successfully: All {total_nodes} nodes collected.",
                    extra={"node": utils.NODE_IP},
                )

        _cleanup_diagnose_files(files_to_cleanup)
        logger.info(f"Diagnose job {job_id} completed", extra={"node": utils.NODE_IP})

    except Exception as e:
        _update_diagnose_job({"status": "failed", "message": str(e), "error": str(e)})
        _cleanup_diagnose_files(files_to_cleanup)
        logger.error(f"Diagnose job {job_id} failed: {e}", extra={"node": utils.NODE_IP})


@SimpleAPIServer.route("/run-diagnose", methods=["POST"], scopes=[ADMIN_ROLE])
def run_diagnose(handler):
    """
    Start diagnose collection. Returns job_id immediately for async processing.

    Use /diagnose-download to get file or check status.

    Throttling behavior:
    - If a job is already running, returns the existing job_id with status "running"
    - If a completed job exists, returns info about it (use cleanup=true to clear)
    - Only starts a new job if no job exists or previous job was cleared

    In HA mode, this will:
    - Pre-check all nodes for management server and CE container health
    - Generate warnings for unreachable nodes or stopped containers
    - Collect diagnose from all reachable nodes
    - Merge results into a single cluster zip file

    Recovery after restart:
        If management server restarted with a completed diagnose job, this endpoint
        will recover the job state and inform the user to download it first.

    Returns:
        JSON response with job_id, status, and message
    """
    global CURRENT_DIAGNOSE_JOB
    logger.info("Diagnose API called", extra={"node": utils.NODE_IP})

    # Load environment variables
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(handler, f"Error loading environment: {error_msg}", 500)

    with _diagnose_job_lock:
        # If no in-memory job, attempt recovery from file system
        if not CURRENT_DIAGNOSE_JOB:
            recovered_job = _recover_diagnose_job_state()
            if recovered_job and recovered_job.get("status") == "completed":
                # Verify the file still exists
                if recovered_job.get("file_path") and os.path.exists(recovered_job["file_path"]):
                    CURRENT_DIAGNOSE_JOB = recovered_job
                    logger.info(
                        f"Recovered completed diagnose job {recovered_job.get('job_id')} from file system",
                        extra={"node": utils.NODE_IP},
                    )

        # Check if a job is already running - throttle redundant requests
        if CURRENT_DIAGNOSE_JOB and CURRENT_DIAGNOSE_JOB.get("status") == "running":
            return {
                "job_id": CURRENT_DIAGNOSE_JOB["job_id"],
                "status": "running",
                "message": "Diagnose already in progress",
            }, 200

        # Check if a completed job exists - inform user to download or clear it
        if CURRENT_DIAGNOSE_JOB and CURRENT_DIAGNOSE_JOB.get("status") == "completed":
            return {
                "job_id": CURRENT_DIAGNOSE_JOB["job_id"],
                "status": "completed",
                "message": "Remove existing diagnose file after download to allow a new diagnosis run",
                "file_name": CURRENT_DIAGNOSE_JOB.get("file_name"),
            }, 200

        job_id = str(uuid.uuid4())
        auth_header = handler.headers.get("Authorization")
        ha_ip_list = AVAILABLE_INPUTS.get("HA_IP_LIST", "")
        is_ha_mode = bool(ha_ip_list and len(ha_ip_list.strip().split(",")) > 1)

        # Clean up all old diagnose files (metadata + zips) - only one job at a time
        _cleanup_all_diagnose_files()

        CURRENT_DIAGNOSE_JOB = {
            "job_id": job_id,
            "status": "running",
            "message": "Starting diagnose...",
            "file_path": None,
            "file_name": None,
            "error": None,
            "node_summary": None,
        }

        # Persist job metadata immediately so other HA nodes can see status
        output_dir = _get_diagnose_output_dir()
        os.makedirs(output_dir, exist_ok=True)
        _save_diagnose_job_metadata(CURRENT_DIAGNOSE_JOB, output_dir)
        logger.info(f"Persisted job metadata for {job_id} to {output_dir}", extra={"node": utils.NODE_IP})

    worker = threading.Thread(
        target=_run_diagnose_worker,
        args=(job_id, auth_header, is_ha_mode, ha_ip_list),
        daemon=True,
    )
    worker.start()

    logger.info(
        f"Diagnose job {job_id} started (HA mode: {is_ha_mode})",
        extra={"node": utils.NODE_IP},
    )
    return {
        "job_id": job_id,
        "status": "running",
        "message": "Diagnose started",
        "is_ha_mode": is_ha_mode,
    }, 202


@SimpleAPIServer.route("/diagnose-status", methods=["GET"], scopes=[ADMIN_ROLE])
def diagnose_status(handler):
    """
    Get the status of the current or last diagnose job.

    Returns:
        JSON response with:
        - job_id: The diagnose job ID (use this for download if status is "completed")
        - status: "running", "completed", "failed", or None
        - message: Human-readable status message
        - file_name: Name of the zip file (only if status is "completed")

    Recovery after restart:
        If management server restarts, this endpoint will attempt to recover
        the job state from metadata files or zip files on disk.
    """
    global CURRENT_DIAGNOSE_JOB

    # Load environment variables
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(handler, f"Error loading environment: {error_msg}", 500)

    with _diagnose_job_lock:
        # If no in-memory job, attempt recovery from file system
        if not CURRENT_DIAGNOSE_JOB:
            logger.info(
                "No in-memory job found, attempting recovery from file system",
                extra={"node": utils.NODE_IP},
            )
            recovered_job = _recover_diagnose_job_state()
            if recovered_job:
                CURRENT_DIAGNOSE_JOB = recovered_job
                logger.info(
                    f"Recovered diagnose job {recovered_job.get('job_id')} from file system",
                    extra={"node": utils.NODE_IP},
                )
        else:
            # Refresh from metadata file to get latest updates from other HA nodes
            job_id = CURRENT_DIAGNOSE_JOB.get("job_id")
            if job_id:
                logger.info(f"Refreshing job {job_id} from metadata file", extra={"node": utils.NODE_IP})
                output_dir = _get_diagnose_output_dir()
                refreshed_job = _load_diagnose_job_metadata(job_id, output_dir)
                if refreshed_job:
                    logger.info(
                        f"Refreshed job {job_id}: old_status={CURRENT_DIAGNOSE_JOB.get('status')}, "
                        f"new_status={refreshed_job.get('status')}",
                        extra={"node": utils.NODE_IP},
                    )
                    CURRENT_DIAGNOSE_JOB = refreshed_job
                else:
                    # Metadata file missing or corrupted - clear in-memory job
                    logger.warning(
                        f"Failed to refresh job {job_id} from metadata file - metadata missing or corrupted. "
                        f"Clearing in-memory job state.",
                        extra={"node": utils.NODE_IP},
                    )
                    _cleanup_all_diagnose_files()
                    CURRENT_DIAGNOSE_JOB = None

        # No job found
        if not CURRENT_DIAGNOSE_JOB:
            logger.info(
                "No diagnose job found after recovery attempt",
                extra={"node": utils.NODE_IP},
            )
            return {
                "job_id": None,
                "status": None,
                "message": "No diagnose job found. Run diagnose first.",
            }, 404

        job_id = CURRENT_DIAGNOSE_JOB["job_id"]
        status = CURRENT_DIAGNOSE_JOB["status"]

        if status == "running":
            return {
                "job_id": job_id,
                "status": "running",
                "message": CURRENT_DIAGNOSE_JOB["message"],
            }, 200

        if status == "failed":
            error_msg = CURRENT_DIAGNOSE_JOB.get("error") or CURRENT_DIAGNOSE_JOB.get("message", "Unknown error")
            # Keep metadata file so user can see error details
            # User can start a new diagnose which will clean up old files
            CURRENT_DIAGNOSE_JOB = None
            return {
                "job_id": job_id,
                "status": "failed",
                "message": error_msg,
            }, 200

        if status == "completed":
            file_path = CURRENT_DIAGNOSE_JOB.get("file_path")
            file_name = CURRENT_DIAGNOSE_JOB.get("file_name")

            # Verify file still exists
            if not file_path or not os.path.exists(file_path):
                _delete_diagnose_job_metadata(job_id)
                CURRENT_DIAGNOSE_JOB = None
                return {
                    "job_id": job_id,
                    "status": "error",
                    "message": "File not found. Run new diagnose.",
                }, 410

            return {
                "job_id": job_id,
                "status": "completed",
                "message": "Diagnose ready for download.",
                "file_name": file_name,
            }, 200

        # Unknown status
        return {
            "job_id": job_id,
            "status": status,
            "message": "Unknown status",
        }, 200


@SimpleAPIServer.route("/diagnose-download", methods=["GET"], scopes=[ADMIN_ROLE])
def diagnose_download(handler):
    """
    Download the diagnose zip file by job_id.

    Query Parameters:
        job_id (required): The job ID to download (obtained from /diagnose-status)
        remove_file (optional): Controls file cleanup after download
            - remove_file=true  → Download ZIP + Delete server files + Reset job state
            - remove_file=false or not passed → Just download ZIP (keep files for re-download)

    Returns:
        - Binary zip file download if job_id is valid and file exists
        - JSON error response otherwise
    """
    global CURRENT_DIAGNOSE_JOB

    parsed_url = urlparse(handler.path)
    query_params = parse_qs(parsed_url.query)
    job_id = query_params.get("job_id", [None])[0]
    cleanup = query_params.get("remove_file", ["false"])[0].lower() == "true"

    if not job_id:
        return {
            "job_id": None,
            "status": "error",
            "message": "job_id is required. Use /diagnose-status to get the job_id.",
        }, 400

    # Load environment variables
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(handler, f"Error loading environment: {error_msg}", 500)

    with _diagnose_job_lock:
        file_path = None
        file_name = None

        # Check if job_id matches current in-memory job
        if CURRENT_DIAGNOSE_JOB and CURRENT_DIAGNOSE_JOB.get("job_id") == job_id:
            if CURRENT_DIAGNOSE_JOB["status"] == "running":
                return {
                    "job_id": job_id,
                    "status": "running",
                    "message": "Diagnose is still running. Please wait.",
                }, 202

            if CURRENT_DIAGNOSE_JOB["status"] == "failed":
                return {
                    "job_id": job_id,
                    "status": "failed",
                    "message": CURRENT_DIAGNOSE_JOB.get("error", "Diagnose failed."),
                }, 200

            if CURRENT_DIAGNOSE_JOB["status"] == "completed":
                file_path = CURRENT_DIAGNOSE_JOB.get("file_path")
                file_name = CURRENT_DIAGNOSE_JOB.get("file_name")

        # If not in memory, try to recover from file system
        if not file_path:
            recovered_job = _recover_diagnose_job_state(job_id)
            if recovered_job:
                file_path = recovered_job.get("file_path")
                file_name = recovered_job.get("file_name")

        # Validate file exists
        if not file_path or not os.path.exists(file_path):
            return {
                "job_id": job_id,
                "status": "not_found",
                "message": f"No file found for job {job_id}. It may have been deleted or expired.",
            }, 404

        # Determine cleanup behavior
        if cleanup:
            _delete_diagnose_job_metadata(job_id)
            if CURRENT_DIAGNOSE_JOB and CURRENT_DIAGNOSE_JOB.get("job_id") == job_id:
                CURRENT_DIAGNOSE_JOB = None
            files_to_cleanup = [file_path]
            logger.info(
                f"Diagnose download (job {job_id}): file will be deleted after download",
                extra={"node": utils.NODE_IP},
            )
        else:
            files_to_cleanup = []
            logger.info(
                f"Diagnose download (job {job_id}): file kept for future downloads",
                extra={"node": utils.NODE_IP},
            )
    return _send_zip_file_download(handler, file_path, file_name, files_to_cleanup=files_to_cleanup)


@SimpleAPIServer.route("/run-diagnose-node", methods=["POST"], scopes=[ADMIN_ROLE])
def run_diagnose_node(handler):
    """
    Run diagnose on a single node and return the zip file.

    This endpoint is used for node-to-node communication in HA mode.
    When the main /run-diagnose endpoint is called on any node in an HA cluster,
    it calls this endpoint on all other nodes to collect their diagnose data.

    This endpoint:
        - Executes ./diagnose script locally on this node
        - Returns the generated zip file as a direct binary download
        - Is NOT intended to be called directly by the UI

    Returns:
        Binary zip file download with Content-Type: application/zip

    Error Response:
        JSON with "detail" field and appropriate HTTP status code
    """
    logger.info("Starting node-only diagnose operation (internal API)", extra={"node": utils.NODE_IP})

    # Load environment variables
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(handler, f"Error loading environment: {error_msg}", 500)

    files_to_cleanup = []

    try:
        # Execute the ./diagnose script on this node
        logger.info("Running diagnose locally for remote collection", extra={"node": utils.NODE_IP})
        success, result = _run_local_diagnose()

        if not success:
            logger.error(f"Node diagnose failed: {result}", extra={"node": utils.NODE_IP})
            return _send_json_error_response(handler, f"Diagnose failed: {result}", 500)

        zip_file_path = result
        files_to_cleanup.append(zip_file_path)

        # Send the zip file directly as binary download
        logger.info(f"Node diagnose completed, sending file: {zip_file_path}", extra={"node": utils.NODE_IP})
        return _send_zip_file_download(handler, zip_file_path, os.path.basename(zip_file_path), files_to_cleanup)

    except Exception as e:
        logger.error(f"Node diagnose operation failed: {str(e)}", extra={"node": utils.NODE_IP})
        _cleanup_diagnose_files(files_to_cleanup)
        return _send_json_error_response(handler, f"Diagnose operation failed: {str(e)}", 500)


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
        skip_cluster = True if query_params.get("skip_cluster", [""])[0].lower() == "true" else False
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




# ==========================================================================
# Pre-flight health check -- mirrors the diagnose implementation above:
# async job, per-node HTTPS fan-out in HA, merged downloadable report.
# ==========================================================================

HEALTHCHECK_OUTPUT_DIR_DEFAULT = "./data/healthcheck_output"
HEALTHCHECK_SCRIPT = "./ce_healthcheck"

# Always `sudo python3 ./ce_healthcheck`, never `{SUDO_PREFIX} ./ce_healthcheck`.
# When this server is already root, SUDO_PREFIX is empty and a bare
# invocation resolves python3 via the shebang from the SERVICE's PATH, not
# sudo's secure_path -- which is what `sudo python3 ./setup` uses. Confirmed
# on a host where those differ (3.12 vs 3.11), flipping a real FAIL to PASS.
HEALTHCHECK_INVOCATION = f"sudo python3 {HEALTHCHECK_SCRIPT}"
CURRENT_HEALTHCHECK_JOB = None
_healthcheck_job_lock = threading.Lock()

# The script is a pre-flight check for an upgrade; the UI only exists on a
# host that already has Cloud Exchange installed, so "install" is not a
# reachable state from there.
HEALTHCHECK_MODE = "upgrade"

# Must match before the shell command is built -- parse_version() runs too
# late to help, since shell=True has already executed by then. Covers real
# CE version shapes (7.0.0-beta.1, 5.1.1-dlp-beta-1) and rejects anything
# starting with "-" so a value can't be read as another flag.
HEALTHCHECK_VERSION_RE = re.compile(
    r"^[vV]?[0-9]+(\.[0-9]+){0,3}([-_.][0-9A-Za-z]+)*$")
HEALTHCHECK_DEPLOYMENTS = ("SA", "HA")


def _validate_healthcheck_params(deployment, target_version):
    """Error string, or None. Shared by both healthcheck routes so the
    internal one can't be looser than the UI-facing one."""
    if deployment not in HEALTHCHECK_DEPLOYMENTS:
        return "deployment must be 'SA' or 'HA'"
    if not target_version:
        return "target_version is required"
    if not HEALTHCHECK_VERSION_RE.match(str(target_version)):
        return "target_version is not a valid Cloud Exchange version string"
    return None


def _read_json_body(handler):
    """Parse a JSON request body, tolerating an empty one."""
    try:
        content_length = int(handler.headers.get("Content-Length", 0))
        if not content_length:
            return {}
        data = json.loads(handler.rfile.read(content_length).decode())
        # A non-dict body (e.g. a JSON array) is truthy but has no .get(),
        # which surfaced as a 500 instead of a 400.
        return data if isinstance(data, dict) else {}
    except (ValueError, json.JSONDecodeError):
        return {}


def _get_healthcheck_output_dir():
    """Shared NFS directory in HA, local directory otherwise.

    Same derivation as _get_diagnose_output_dir(), so a job started on one
    node is visible to the others.
    """
    shared_dir_base_path = "/".join(
        (AVAILABLE_INPUTS.get("HA_NFS_DATA_DIRECTORY", "").strip().rstrip("/").split("/"))[:-1]
    )
    if shared_dir_base_path:
        output_dir = os.path.join(shared_dir_base_path, "data", "healthcheck_output")
    else:
        output_dir = HEALTHCHECK_OUTPUT_DIR_DEFAULT
    logger.debug(f"Health check directory: {output_dir}")
    return output_dir


def _healthcheck_job_metadata_path(job_id, output_dir=None):
    if output_dir is None:
        output_dir = _get_healthcheck_output_dir()
    return os.path.join(output_dir, f".healthcheck_job_{job_id}.json")


def _save_healthcheck_job_metadata(job_data, output_dir=None):
    """Persist job state so other HA nodes (and a restarted server) see it."""
    try:
        if output_dir is None:
            output_dir = _get_healthcheck_output_dir()
        os.makedirs(output_dir, exist_ok=True)
        path = _healthcheck_job_metadata_path(job_data["job_id"], output_dir)
        with open(path, "w") as handle:
            json.dump(job_data, handle)
        return True
    except Exception as e:
        logger.error(
            f"Failed to save health check job metadata: {e}",
            extra={"node": utils.NODE_IP},
        )
        return False


def _load_healthcheck_job_metadata(job_id, output_dir=None):
    try:
        if output_dir is None:
            output_dir = _get_healthcheck_output_dir()
        path = _healthcheck_job_metadata_path(job_id, output_dir)
        if not os.path.exists(path):
            return None
        with open(path) as handle:
            return json.load(handle)
    except Exception as e:
        logger.error(
            f"Failed to load health check job metadata: {e}",
            extra={"node": utils.NODE_IP},
        )
        return None


def _cleanup_all_healthcheck_files(output_dir=None, exclude_job_id=None):
    """Remove previous health check job artifacts, keeping one run's worth.

    Mirrors _cleanup_all_diagnose_files(): the run entry point refuses to
    start while a job is running, so only one job's files are ever live.
    Without this, every run left its metadata, JSON and HTML behind for good.
    """
    try:
        if output_dir is None:
            output_dir = _get_healthcheck_output_dir()
        if not os.path.exists(output_dir):
            return

        for filename in os.listdir(output_dir):
            is_meta = (filename.startswith(".healthcheck_job_")
                       and filename.endswith(".json"))
            is_payloads = (filename.startswith(".healthcheck_payloads_")
                           and filename.endswith(".json"))
            is_report = (filename.startswith("ce_healthcheck_")
                         and filename.endswith((".json", ".html")))
            if not (is_meta or is_payloads or is_report):
                continue
            if exclude_job_id and exclude_job_id in filename:
                continue
            try:
                os.remove(os.path.join(output_dir, filename))
                logger.info(f"Cleaned up old health check file: {filename}",
                            extra={"node": utils.NODE_IP})
            except Exception as e:
                logger.warning(f"Failed to cleanup {filename}: {e}",
                               extra={"node": utils.NODE_IP})
    except Exception as e:
        logger.warning(f"Health check cleanup failed: {e}",
                       extra={"node": utils.NODE_IP})


def _fail_if_orphaned(job):
    """Report a persisted "running" job as failed -- it cannot still be live.

    Only reached when nothing is in memory, and the worker is a thread of
    this process: a job still running would have been in CURRENT_HEALTHCHECK_JOB.
    So a "running" status read back from disk always means the server that
    owned it is gone. Deliberately not keyed on the recorded server_pid --
    PIDs are reused, and the in-memory check above is the stronger signal.
    """
    if not isinstance(job, dict) or job.get("status") != "running":
        return job
    job["status"] = "failed"
    job["message"] = "Health check interrupted"
    job["error"] = (
        "The management server restarted while this health check was "
        "running. Run it again."
    )
    return job


def _recover_healthcheck_job_state(job_id=None):
    """Load the newest persisted job from disk when nothing is in memory
    (e.g. after a server restart). Mirrors _recover_diagnose_job_state()."""
    global CURRENT_HEALTHCHECK_JOB
    try:
        output_dir = _get_healthcheck_output_dir()
        if job_id:
            recovered = _load_healthcheck_job_metadata(job_id, output_dir)
            if recovered:
                recovered = _fail_if_orphaned(recovered)
                CURRENT_HEALTHCHECK_JOB = recovered
            return recovered

        if not os.path.isdir(output_dir):
            return None
        candidates = [
            os.path.join(output_dir, name)
            for name in os.listdir(output_dir)
            if name.startswith(".healthcheck_job_") and name.endswith(".json")
        ]
        if not candidates:
            return None
        newest = max(candidates, key=os.path.getmtime)
        with open(newest) as handle:
            recovered = json.load(handle)
        recovered = _fail_if_orphaned(recovered)
        CURRENT_HEALTHCHECK_JOB = recovered
        return recovered
    except Exception as e:
        logger.error(
            f"Failed to recover health check job state: {e}",
            extra={"node": utils.NODE_IP},
        )
        return None


def _update_healthcheck_job(updates):
    """Update the in-memory job and persist it in one step."""
    global CURRENT_HEALTHCHECK_JOB
    with _healthcheck_job_lock:
        if CURRENT_HEALTHCHECK_JOB is None:
            return
        CURRENT_HEALTHCHECK_JOB.update(updates)
        _save_healthcheck_job_metadata(CURRENT_HEALTHCHECK_JOB)


def _run_local_healthcheck(deployment, target_version, manifest_url=None):
    """Run ./ce_healthcheck on this node and return its parsed JSON report.

    Exit-code contract -- this is the part that is easy to get wrong:
        0  every check passed
        1  the run succeeded and one or more checks FAILED
        2  the check definitions could not be obtained; nothing ran

    Exit 1 is a normal, complete result: it is the answer "this host is not
    ready", and its report is fully populated. Only 2 (or unparseable
    output) is an actual error. Treating any non-zero code as a failure --
    which is what _run_local_diagnose does, correctly, for diagnose -- would
    turn every genuinely-unready host into a server error.

    Returns:
        tuple: (success: bool, result: dict|str)
    """
    # shlex.quote every interpolated value, not just the URL -- deployment
    # and target_version previously reached shell=True unquoted (RCE as root).
    command = (
        f"{HEALTHCHECK_INVOCATION} --quiet --json "
        f"--mode {shlex.quote(HEALTHCHECK_MODE)} "
        f"--deployment {shlex.quote(str(deployment))} "
        f"--target-version {shlex.quote(str(target_version))}"
    )
    if manifest_url:
        command = f"{command} --manifest-url {shlex.quote(str(manifest_url))}"

    logger.info(f"Running health check: {command}", extra={"node": utils.NODE_IP})

    stdout_chunks = []
    stderr_output = []
    return_code = 0
    try:
        for message in execute_command(command, shell=True):
            msg_type = message.get("type", "")
            if msg_type == "stdout":
                stdout_chunks.append(message.get("message", ""))
            elif msg_type == "stderr":
                content = message.get("message", "").strip()
                if content:
                    stderr_output.append(content)
            elif msg_type == "returncode":
                return_code = message.get("code", 0)
    except Exception as e:
        logger.error(f"Error running health check: {e}", extra={"node": utils.NODE_IP})
        return False, f"Error running health check: {e}"

    raw = "".join(stdout_chunks).strip()

    if return_code not in (0, 1):
        # Exit 2 explains itself in a JSON object on STDOUT, not stderr --
        # falling back to stderr alone would report "Unknown error".
        detail = ""
        try:
            failure = json.loads(raw)
            if isinstance(failure, dict):
                detail = failure.get("error") or ""
                if failure.get("detail"):
                    detail = f"{detail} {failure['detail']}".strip()
        except ValueError:
            pass
        if not detail:
            detail = "; ".join(stderr_output) if stderr_output else "Unknown error"
        return False, (
            f"Health check could not run (exit {return_code}): {detail}"
        )
    try:
        payload = json.loads(raw)
    except ValueError as e:
        logger.error(
            f"Health check output was not valid JSON: {e}",
            extra={"node": utils.NODE_IP},
        )
        return False, "Health check produced no readable report"

    return True, payload


def _collect_remote_healthcheck(node_ip, auth_header, deployment, target_version,
                                manifest_url=None):
    """Run the health check on a peer node and return its report.

    Node-to-node HTTPS carrying the caller's own auth header, exactly as
    _collect_remote_diagnose does -- no SSH, no additional credentials.
    """
    try:
        payload_body = {"deployment": deployment,
                        "target_version": target_version}
        if manifest_url:
            payload_body["manifest_url"] = manifest_url

        for response in check_management_server(
            node_ip=node_ip,
            handler=None,
            auth_header=auth_header,
            endpoint="/api/management/run-healthcheck-node",
            method="POST",
            protocol="https",
            should_stream=False,
            payload=payload_body,
        ):
            if isinstance(response, tuple) and len(response) >= 2:
                payload, status = response[0], response[1]
                if status == 200 and isinstance(payload, dict):
                    return True, payload
                detail = (
                    payload.get("detail")
                    if isinstance(payload, dict)
                    else str(payload)
                )
                return False, detail or f"HTTP {status}"
            if isinstance(response, dict):
                return True, response
            break
    except Exception as e:
        logger.error(
            f"Failed to collect health check from {node_ip}: {e}",
            extra={"node": utils.NODE_IP},
        )
        return False, str(e)

    return False, "No response from node"


def _merge_healthcheck_summaries(nodes):
    """Cluster-wide totals plus a per-node breakdown.

    Unreachable nodes are counted separately and never folded into the
    healthy totals: a node that was not checked must not be able to make a
    partial run look like a clean one.
    """
    totals = {
        "total": 0, "passed": 0, "warned": 0,
        "failed": 0, "skipped": 0, "not_verified": 0,
    }
    nodes_summary = []
    for entry in nodes:
        node_ip = entry.get("node")
        if entry.get("unreachable"):
            nodes_summary.append({
                "node": node_ip,
                "reachable": False,
                "error": entry.get("error"),
            })
            continue
        summary = (entry.get("payload") or {}).get("summary") or {}
        for key in totals:
            totals[key] += summary.get(key, 0)
        nodes_summary.append({
            "node": node_ip,
            "reachable": True,
            "summary": summary,
        })

    unreachable = [n for n in nodes_summary if not n["reachable"]]
    return {
        "totals": totals,
        "nodes": nodes_summary,
        "nodes_checked": len(nodes_summary) - len(unreachable),
        "nodes_unreachable": len(unreachable),
    }


def _write_healthcheck_reports(job_id, nodes, output_dir):
    """Write the merged JSON, and render the merged HTML via the script.

    The HTML is rendered by ce_healthcheck itself (--render-html) rather
    than here: the report renderer lives inside that single self-contained
    file, which is the only piece of the health check that ships, so there
    is no importable module to call.
    """
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"ce_healthcheck_{job_id}.json")
    html_path = os.path.join(output_dir, f"ce_healthcheck_{job_id}.html")

    document = {
        "job_id": job_id,
        "summary": _merge_healthcheck_summaries(nodes),
        "nodes": nodes,
    }
    with open(json_path, "w") as handle:
        json.dump(document, handle, indent=2, default=str)

    payload_path = os.path.join(output_dir, f".healthcheck_payloads_{job_id}.json")
    with open(payload_path, "w") as handle:
        json.dump({"nodes": nodes}, handle, default=str)

    # Server-derived paths, but still reach shell=True -- quoted regardless.
    command = (
        f"{HEALTHCHECK_INVOCATION} "
        f"--render-html {shlex.quote(payload_path)} "
        f"--html {shlex.quote(html_path)}"
    )
    return_code = 0
    try:
        for message in execute_command(command, shell=True):
            if message.get("type") == "returncode":
                return_code = message.get("code", 0)
    except Exception as e:
        logger.error(
            f"Failed to render health check HTML: {e}",
            extra={"node": utils.NODE_IP},
        )
        return_code = 1
    finally:
        try:
            os.remove(payload_path)
        except OSError:
            pass

    if return_code != 0 or not os.path.exists(html_path):
        logger.warning(
            "Health check HTML rendering failed; JSON report is still available",
            extra={"node": utils.NODE_IP},
        )
        html_path = None

    return json_path, html_path


def _run_healthcheck_worker(job_id, auth_header, is_ha_mode, ha_ip_list,
                            deployment, target_version, manifest_url=None):
    """Background worker: run locally, fan out in HA, merge, write reports."""
    try:
        nodes = []
        # Same resolution as _run_diagnose_worker: utils.NODE_IP is only
        # assigned during HA setup, so prefer the env HA_CURRENT_NODE. This
        # value decides which node counts as local, so getting it wrong
        # makes this node fan out to itself and skip a real peer.
        current_node_ip = AVAILABLE_INPUTS.get("HA_CURRENT_NODE", "").strip() or (
            utils.NODE_IP.strip() if utils.NODE_IP else ""
        )

        _update_healthcheck_job({"message": "Running checks on this node..."})
        success, result = _run_local_healthcheck(
            deployment, target_version, manifest_url)
        if not success:
            _update_healthcheck_job({
                "status": "failed",
                "message": "Health check failed",
                "error": result,
            })
            return

        nodes.append({
            "node": current_node_ip,
            "label": f"Node {current_node_ip}" if current_node_ip else "This node",
            "payload": result,
        })

        if is_ha_mode:
            all_ips = [ip.strip() for ip in ha_ip_list.split(",") if ip.strip()]
            peers = [ip for ip in all_ips if ip != current_node_ip]
            for index, node_ip in enumerate(peers, start=1):
                _update_healthcheck_job({
                    "message": f"Collecting from node {index} of {len(peers)}...",
                })
                ok, peer_result = _collect_remote_healthcheck(
                    node_ip, auth_header, deployment, target_version,
                    manifest_url)
                if ok:
                    nodes.append({
                        "node": node_ip,
                        "label": f"Node {node_ip}",
                        "payload": peer_result,
                    })
                else:
                    # Skip, do not abort -- matching _run_diagnose_worker. The
                    # node is still recorded so the report can show it was not
                    # checked rather than omitting it silently.
                    logger.warning(
                        f"Health check: {node_ip} unreachable (skipped): {peer_result}",
                        extra={"node": utils.NODE_IP},
                    )
                    nodes.append({
                        "node": node_ip,
                        "label": f"Node {node_ip}",
                        "unreachable": True,
                        "error": f"Management server unreachable (skipped): {peer_result}",
                    })

        _update_healthcheck_job({"message": "Building report..."})
        output_dir = _get_healthcheck_output_dir()
        json_path, html_path = _write_healthcheck_reports(job_id, nodes, output_dir)

        summary = _merge_healthcheck_summaries(nodes)
        _update_healthcheck_job({
            "status": "completed",
            "message": "Health check completed",
            "json_path": json_path,
            "html_path": html_path,
            "summary": summary,
            "error": None,
        })
        logger.info(
            f"Health check job {job_id} completed "
            f"({summary['nodes_checked']} node(s) checked, "
            f"{summary['nodes_unreachable']} unreachable)",
            extra={"node": utils.NODE_IP},
        )
    except Exception as e:
        logger.error(
            f"Health check job {job_id} failed: {e}",
            extra={"node": utils.NODE_IP},
        )
        _update_healthcheck_job({
            "status": "failed",
            "message": "Health check failed",
            "error": str(e),
        })


@SimpleAPIServer.route("/run-healthcheck", methods=["POST"], scopes=[ADMIN_ROLE])
def run_healthcheck(handler):
    """Start a pre-flight health check. Returns a job_id immediately.

    Body (all optional; sensible defaults are derived from this host):
        {"deployment": "SA"|"HA", "target_version": "7.0.0",
         "manifest_url": "https://..."}

    In HA this runs on every reachable node and merges the results. Nodes
    that cannot be reached are skipped and reported as unreachable rather
    than failing the job.
    """
    global CURRENT_HEALTHCHECK_JOB
    logger.info("Health check API called", extra={"node": utils.NODE_IP})

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(
            handler, f"Error loading environment: {error_msg}", 500)

    body = _read_json_body(handler)

    ha_ip_list = AVAILABLE_INPUTS.get("HA_IP_LIST", "")
    is_ha_mode = bool(ha_ip_list and len(ha_ip_list.strip().split(",")) > 1)

    deployment = body.get("deployment") or ("HA" if is_ha_mode else "SA")
    target_version = body.get("target_version")
    param_error = _validate_healthcheck_params(deployment, target_version)
    if param_error:
        return _send_json_error_response(handler, param_error, 400)

    manifest_url = body.get("manifest_url")

    with _healthcheck_job_lock:
        if CURRENT_HEALTHCHECK_JOB and CURRENT_HEALTHCHECK_JOB.get("status") == "running":
            return {
                "job_id": CURRENT_HEALTHCHECK_JOB["job_id"],
                "status": "running",
                "message": "Health check already in progress",
            }, 200

        job_id = str(uuid.uuid4())
        auth_header = handler.headers.get("Authorization")

        CURRENT_HEALTHCHECK_JOB = {
            "job_id": job_id,
            "status": "running",
            "message": "Starting health check...",
            "json_path": None,
            "html_path": None,
            "summary": None,
            "error": None,
            "deployment": deployment,
            "target_version": target_version,
            # Recorded for diagnostics, and for a future orphan reaper to
            # gate on. Not consulted by _fail_if_orphaned(), which has a
            # stronger signal -- see its docstring.
            "server_pid": os.getpid(),
            "started_at": time.time(),
        }
        output_dir = _get_healthcheck_output_dir()
        os.makedirs(output_dir, exist_ok=True)
        # Only one job's artifacts are kept, as in the diagnose flow.
        _cleanup_all_healthcheck_files(output_dir, exclude_job_id=job_id)
        _save_healthcheck_job_metadata(CURRENT_HEALTHCHECK_JOB, output_dir)

    worker = threading.Thread(
        target=_run_healthcheck_worker,
        args=(job_id, auth_header, is_ha_mode, ha_ip_list, deployment,
              target_version, manifest_url),
        daemon=True,
    )
    worker.start()

    logger.info(
        f"Health check job {job_id} started (HA mode: {is_ha_mode})",
        extra={"node": utils.NODE_IP},
    )
    return {
        "job_id": job_id,
        "status": "running",
        "message": "Health check started",
        "is_ha_mode": is_ha_mode,
    }, 202


@SimpleAPIServer.route("/healthcheck-status", methods=["GET"], scopes=[ADMIN_ROLE])
def healthcheck_status(handler):
    """Status of the current or last health check job."""
    global CURRENT_HEALTHCHECK_JOB

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(
            handler, f"Error loading environment: {error_msg}", 500)

    with _healthcheck_job_lock:
        if CURRENT_HEALTHCHECK_JOB:
            # Refresh from disk so a job driven by another HA node is current.
            job_id = CURRENT_HEALTHCHECK_JOB.get("job_id")
            refreshed = _load_healthcheck_job_metadata(job_id)
            if refreshed:
                CURRENT_HEALTHCHECK_JOB = refreshed
        else:
            # Nothing in memory: this server may have restarted since the run.
            _recover_healthcheck_job_state()

        if not CURRENT_HEALTHCHECK_JOB:
            return {"status": "not_found", "message": "No health check has been run"}, 200

        job = CURRENT_HEALTHCHECK_JOB
        response = {
            "job_id": job.get("job_id"),
            "status": job.get("status"),
            "message": job.get("message"),
            "deployment": job.get("deployment"),
            "target_version": job.get("target_version"),
        }
        if job.get("status") == "completed":
            response["summary"] = job.get("summary")
            response["formats"] = ["json"] + (["html"] if job.get("html_path") else [])
        if job.get("error"):
            response["error"] = job["error"]
        return response, 200


@SimpleAPIServer.route("/healthcheck-download", methods=["GET"], scopes=[ADMIN_ROLE])
def healthcheck_download(handler):
    """Download the merged report: ?format=html (default) or ?format=json."""
    global CURRENT_HEALTHCHECK_JOB

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(
            handler, f"Error loading environment: {error_msg}", 500)

    query_params = parse_qs(urlparse(handler.path).query)
    fmt = (query_params.get("format") or ["html"])[0]

    with _healthcheck_job_lock:
        job = CURRENT_HEALTHCHECK_JOB
        if job and job.get("job_id"):
            refreshed = _load_healthcheck_job_metadata(job["job_id"])
            if refreshed:
                job = CURRENT_HEALTHCHECK_JOB = refreshed
        elif not job:
            job = _recover_healthcheck_job_state()

    if not job or job.get("status") != "completed":
        return _send_json_error_response(
            handler, "No completed health check report is available", 404)

    path = job.get("html_path") if fmt == "html" else job.get("json_path")
    if not path or not os.path.exists(path):
        return _send_json_error_response(
            handler, f"Report is not available in {fmt} format", 404)

    content_type = "text/html" if fmt == "html" else "application/json"
    try:
        with open(path, "rb") as handle:
            content = handle.read()
    except OSError as e:
        return _send_json_error_response(handler, f"Could not read report: {e}", 500)

    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header(
        "Content-Disposition",
        f'attachment; filename="{os.path.basename(path)}"')
    handler.send_header("Content-Length", str(len(content)))
    handler.end_headers()
    handler.wfile.write(content)
    return None


@SimpleAPIServer.route("/healthcheck-versions", methods=["GET"], scopes=[ADMIN_ROLE])
def healthcheck_versions(handler):
    """Target CE versions the check definitions cover, for the dialog's
    version dropdown. Empty only on a fetch/parse failure (`error` is set)."""
    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(
            handler, f"Error loading environment: {error_msg}", 500)

    params = parse_qs(urlparse(handler.path).query)
    manifest_url = (params.get("manifest_url") or [None])[0]

    command = f"{HEALTHCHECK_INVOCATION} --list-versions"
    if manifest_url:
        command = f"{command} --manifest-url {shlex.quote(str(manifest_url))}"

    stdout_chunks = []
    return_code = 0
    try:
        for message in execute_command(command, shell=True):
            if message.get("type") == "stdout":
                stdout_chunks.append(message.get("message", ""))
            elif message.get("type") == "returncode":
                return_code = message.get("code", 0)
    except Exception as e:
        logger.error(f"Could not list health check versions: {e}",
                     extra={"node": utils.NODE_IP})
        return {"versions": [], "default": None,
                "error": str(e)}, 200

    raw = "".join(stdout_chunks).strip()
    try:
        payload = json.loads(raw)
    except ValueError:
        logger.warning(
            "Health check --list-versions produced no readable output",
            extra={"node": utils.NODE_IP})
        return {"versions": [], "default": None}, 200

    if return_code != 0 and not payload.get("versions"):
        # Not fatal: the UI falls back to free text.
        return {"versions": [], "default": payload.get("default"),
                "error": payload.get("error")}, 200
    return payload, 200


@SimpleAPIServer.route("/healthcheck-results", methods=["GET"], scopes=[ADMIN_ROLE])
def healthcheck_results(handler):
    """Full per-check results of the last completed run.

    The polled status endpoint deliberately returns counts only; this returns
    every check with its name, level and remedy so the UI can render an
    expandable per-node breakdown without re-downloading the report file.
    """
    global CURRENT_HEALTHCHECK_JOB

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(
            handler, f"Error loading environment: {error_msg}", 500)

    with _healthcheck_job_lock:
        job = CURRENT_HEALTHCHECK_JOB
        if job and job.get("job_id"):
            refreshed = _load_healthcheck_job_metadata(job["job_id"])
            if refreshed:
                job = CURRENT_HEALTHCHECK_JOB = refreshed
        elif not job:
            job = _recover_healthcheck_job_state()

    if not job or job.get("status") != "completed":
        return _send_json_error_response(
            handler, "No completed health check report is available", 404)

    json_path = job.get("json_path")
    if not json_path or not os.path.exists(json_path):
        return _send_json_error_response(
            handler, "The health check report file is no longer available", 404)

    try:
        with open(json_path) as handle:
            document = json.load(handle)
    except (OSError, ValueError) as e:
        return _send_json_error_response(
            handler, f"Could not read the health check report: {e}", 500)

    # Trim to what a results view needs. The full facts blob is large and is
    # only useful in the downloadable report, so it is deliberately omitted.
    nodes = []
    for entry in document.get("nodes") or []:
        if entry.get("unreachable"):
            nodes.append({
                "node": entry.get("node"),
                "label": entry.get("label"),
                "reachable": False,
                "error": entry.get("error"),
                "results": [],
            })
            continue
        payload = entry.get("payload") or {}
        nodes.append({
            "node": entry.get("node"),
            "label": entry.get("label"),
            "reachable": True,
            "summary": payload.get("summary"),
            "meta": payload.get("meta"),
            "results": [
                {
                    "id": r.get("id"),
                    "label": r.get("label"),
                    "level": r.get("level"),
                    "type": r.get("type"),
                    "category": r.get("category"),
                    "remedy": r.get("remedy"),
                    "actual": r.get("actual"),
                    "expected": r.get("expected"),
                }
                for r in payload.get("results") or []
            ],
        })

    return {
        "job_id": document.get("job_id"),
        "summary": document.get("summary"),
        "nodes": nodes,
    }, 200


@SimpleAPIServer.route("/run-healthcheck-node", methods=["POST"], scopes=[ADMIN_ROLE])
def run_healthcheck_node(handler):
    """Run the health check on this node only and return its JSON report.

    Node-to-node communication in HA mode; not called by the UI directly.
    """
    logger.info(
        "Starting node-only health check (internal API)",
        extra={"node": utils.NODE_IP},
    )

    success, error_msg = load_environment_from_multiple_sources(handler)
    if not success:
        return _send_json_error_response(
            handler, f"Error loading environment: {error_msg}", 500)

    body = _read_json_body(handler)

    # Same validation as the UI-facing route -- "internal" isn't a security
    # boundary; this reaches the same shell command builder.
    deployment = body.get("deployment") or "HA"
    target_version = body.get("target_version")
    param_error = _validate_healthcheck_params(deployment, target_version)
    if param_error:
        return _send_json_error_response(handler, param_error, 400)

    ok, result = _run_local_healthcheck(
        deployment, target_version, body.get("manifest_url"))
    if not ok:
        return _send_json_error_response(handler, result, 500)
    return result, 200


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
