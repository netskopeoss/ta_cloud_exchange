"""Migrate CE Script."""
import atexit
import ipaddress
import os
import re
import subprocess
from enum import Enum
from getpass import getpass


class Color(str, Enum):
    """Color enum."""

    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def validate_hostname(hostname):
    """Validate hostname."""
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        raise ValueError("Invalid hostname.")


def validate_ip(ip):
    """Validate IP."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("Invalid IP address.")


def validate_path(path):
    """Validate path."""
    if not re.match(r"^[\w./-]+$", path) or not os.path.exists(path):
        raise ValueError("Path does not exist or is invalid.")


def print_warning(message):
    """Print warning."""
    print(f"\033[1;93m[!] \033[0;37m{message}")


def print_fail(message):
    """Print fail."""
    print(f"\033[1;31m[F] \033[1;37m{message}\033[0;37m")


def print_pass(message):
    """Print pass."""
    print(f"\033[0;32m[P] \033[0;37m{message}")


def print_with_color(message, color: Color):
    """Print with color."""
    print(color + message + color.END)


def isRedHat():
    """Check if Red Hat OS."""
    try:
        if os.path.exists("/etc/redhat-release"):
            with open("/etc/redhat-release") as f:
                content = f.readline()
                if content.startswith("Red Hat"):
                    return True
                else:
                    return False
        else:
            return False
    except Exception as error:
        print_fail("Failed to check the OS. Error: " + str(error))
        exit(1)


def isRedHat79():
    """Check if Red Hat 7.9 OS."""
    try:
        if os.path.exists("/etc/redhat-release"):
            with open("/etc/redhat-release") as f:
                content = f.readline()
                if content.startswith("Red Hat") and "7.9" in content:
                    return True
                else:
                    return False
        else:
            return False
    except Exception as error:
        print_fail("Failed to check the OS. Error: " + str(error))
        exit(1)


def run_ssh_scp(cmd, password, *args, print_output=True):
    """Run ssh/scp command and return data."""
    pid, fd = os.forkpty()
    if pid == 0:  # child
        os.execlp(cmd, *args)
    data = None
    success = False
    while True:
        try:
            data = os.read(fd, 1024)
        except OSError:
            return data, True
        if not data:
            return data, success
        data = data.decode().lower()
        if "password:" in data:  # ssh prompt
            password_input = f"{password}\n"
            os.write(fd, password_input.encode())
        elif "passphrase for key" in data:
            passphrase_input = f"{password}\n"
            os.write(fd, passphrase_input.encode())
        elif "are you sure you want to continue" in data:
            os.write(fd, b"yes\n")
        if "permission denied" in data:
            return data, False
        elif "connection timed out" in data:
            return data, False
        elif "usage:" in data:
            return data, False
        elif "cannot create" in data:
            return data, False
        else:
            if print_output:
                print(data)


backup_zip = "ce_backup.zip"
remote_user = None
remote_host = None
remote_password = None
remote_ce_dir = None
auth_method = None
ssh_auth = []
shared_drive_path = None
maintenance_password = None
ce_as_a_vm_dest = False
envs = None


def load_env():
    """Load environment variables."""
    global envs
    if os.path.exists(".env"):
        with open(".env", "r") as f:
            pwds = {
                line.split("=")[0].strip(): line.split("=")[1].strip()
                for line in f.readlines()
                if line and line.split("=")
            }
            envs = pwds
    else:
        print_fail(
            "Could not load environment variables as no .env "
            "file found. Exiting..."
        )
        exit(1)


def stop():
    """Stop the CE."""
    print_with_color(
        f"{Color.BOLD}Running the stop script...",
        Color.YELLOW
    )
    try:
        subprocess.run(["./stop"], check=True)
        print_pass("Stop script executed successfully.")
    except Exception as error:
        print_fail("Failed to stop the CE. Error: " + str(error))
        exit(1)


def reset():
    """Reset the CE."""
    print_with_color(
        f"{Color.BOLD}Running the reset script...",
        Color.YELLOW
    )
    try:
        subprocess.run(["git", "reset", "--hard"], check=True)
        subprocess.run(["git", "pull"], check=True)
        print_pass("Reset script executed successfully.")
    except Exception as error:
        print_fail("Failed to reset the CE. Error: " + str(error))
        exit(1)


def backup(type):
    """Backup the CE folder."""
    print_with_color(
        f"{Color.BOLD}Zipping the backup files...",
        Color.YELLOW
    )
    try:
        local_backup_path = "./data"
        global backup_zip
        validate_path(local_backup_path)
        if type == Steps.BACKUP_RABBITMQ_AND_MONGO:
            subprocess.run(
                [
                    "zip", "-r", backup_zip,
                    os.path.join(local_backup_path, "mongo-data"),
                    os.path.join(local_backup_path, "rabbitmq", "data")
                ],
                check=True,
            )
            print_pass(
                "Backup files zipped successfully for mongo-data and rabbitmq."
            )
        elif type == Steps.BACKUP_CUSTOM_PLUGINS:
            if not os.path.exists(
                os.path.join(local_backup_path, "custom_plugins")
            ):
                print_with_color(
                    "Folder for custom plugins not found. Skipping backup.",
                    Color.BOLD
                )
                return
            subprocess.run(
                [
                    "zip",
                    "-r",
                    backup_zip,
                    os.path.join(local_backup_path, "custom_plugins"),
                ],
                check=True,
            )
            print_pass("Backup files zipped successfully for custom plugins.")
        elif type == Steps.BACKUP_REPOS:
            if not os.path.exists(
                os.path.join(local_backup_path, "repos")
            ):
                print_with_color(
                    "Repos folder not found. Skipping backup.",
                    Color.BOLD
                )
                return
            subprocess.run(
                [
                    "zip",
                    "-r",
                    backup_zip,
                    os.path.join(local_backup_path, "repos"),
                ],
                check=True,
            )
            print_pass("Backup files zipped successfully for repos.")
        elif type == Steps.BACKUP_PLUGIN:
            if not os.path.exists(
                os.path.join(local_backup_path, "plugins")
            ):
                print_with_color(
                    "Plugins folder not found. Skipping backup.",
                    Color.BOLD
                )
                return
            subprocess.run(
                [
                    "zip",
                    "-r",
                    backup_zip,
                    os.path.join(local_backup_path, "plugins"),
                ],
                check=True,
            )
            print_pass("Backup files zipped successfully for plugins.")
        else:
            raise ValueError("Invalid backup type.")
    except Exception as error:
        print_fail("Failed to zip the backup files. Error: " + str(error))
        exit(1)


def get_ssh_credentials():
    """Get SSH credentials."""
    global remote_user
    global remote_host
    global remote_password
    global remote_ce_dir
    global ce_as_a_vm_dest
    global ssh_auth
    try:
        tried = 0
        while not remote_user and tried < 3:
            remote_user = input(
                "Enter the destination machine's username{}: ".format(
                    f" ({3-tried} out of 3 tries remaining)"
                    if tried > 0 else ""
                )
            ).strip()
            if not remote_user:
                print_warning(
                    "Destination machine's username cannot be empty."
                )
            tried += 1
        if not remote_user:
            raise ValueError(
                "Invalid username provided after 3 tries. Exiting..."
            )
        tried = 0
        while not remote_host and tried < 3:
            remote_host = input(
                "Enter the destination machine's host IP or domain{}: ".format(
                    f" ({3-tried} out of 3 tries remaining)"
                    if tried > 0 else ""
                )
            ).strip()
            try:
                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", remote_host):
                    validate_ip(remote_host)
                else:
                    validate_hostname(remote_host)
            except ValueError as err:
                remote_host = None
                print_warning(str(err))
            tried += 1
        if not remote_host:
            raise ValueError(
                "Invalid hostname provided after 3 tries. Exiting..."
            )
        auth_method = None
        tried = 0
        while not auth_method and tried < 3:
            try:
                auth_method = (
                    input(
                        "Select authentication method for the SSH "
                        "connection{}: \n"
                        "1. pem\n"
                        "2. password\n"
                        "> "
                        .format(
                            f" ({3-tried} out of 3 tries remaining)"
                            if tried > 0 else ""
                        )
                    )
                    .strip()
                    .lower()
                )

                ssh_auth = []
                if auth_method in ["1", "pem"]:
                    pem_file_path = input(
                        "Enter the full path to your .pem file: "
                    ).strip()
                    validate_path(pem_file_path)
                    remote_password = getpass(
                        "Enter the password for your .pem file: "
                    ).strip()
                    if not remote_password:
                        confirm = input(
                            "You have entered an empty password. Are you sure"
                            " that password is not required for .pem file? "
                            "(y/n) [default: n]: "
                        ).strip().lower()
                        if confirm not in ['y', 'yes']:
                            raise ValueError(
                                "Password cannot be empty for .pem file."
                            )
                        else:
                            remote_password = ""
                    ssh_auth = ["-i", pem_file_path]
                elif auth_method in ["2", "password"]:
                    remote_password = getpass(
                        "Enter the destination machine's password "
                        f"for user {remote_user}: "
                    ).strip()
                    if not remote_password:
                        raise ValueError(
                            "Destination machine's password cannot be empty."
                        )
                else:
                    auth_method = None
                    print_warning(
                        "Invalid authentication way provided for SSH "
                        "authentication. Valid authentication ways are "
                        "'pem (1)' and 'password (2)'."
                    )
            except ValueError as err:
                auth_method = None
                print_warning(str(err))
            tried += 1
        if not auth_method:
            raise ValueError(
                "Invalid authentication way provided after 3 tries. Exiting..."
            )
        if ce_as_a_vm_dest:
            print_warning(
                "Destination is CE as a VM so setting destination directory "
                "as /opt/cloudexchange/cloudexchange"
            )
        else:
            tried = 0
            while not remote_ce_dir and tried < 3:
                remote_ce_dir = input(
                    "Enter the path to the cloud exchange directory "
                    "on the destination machine{}: ".format(
                        f" ({3-tried} out of 3 tries remaining)"
                        if tried > 0 else ""
                    )
                ).strip().rstrip("/")
                output, success = run_ssh_scp(
                    "ssh",
                    remote_password,
                    "ssh",
                    *ssh_auth,
                    f"{remote_user}@{remote_host}",
                    f"[ -d {remote_ce_dir} ] && echo true || echo false",
                    print_output=False
                )
                if not success:
                    print_warning(
                        "Unable to connect with SSH credentials. "
                        "Got: {}".format(
                            output
                        )
                    )
                    remote_ce_dir = None
                if output == "false":
                    print_warning(
                        f"{remote_ce_dir} does not exist on the"
                        " destination machine."
                    )
                    remote_ce_dir = None
                tried += 1
            if not remote_ce_dir:
                raise ValueError(
                    "Invalid destination path provided after 3 tries. "
                    "Exiting..."
                )
            print_with_color(
                "'data' folder from the current system will be copied to "
                f"the destination VM at: {remote_ce_dir}",
                Color.BOLD
            )
    except Exception as error:
        print_fail(
            "Failed to connect with SSH credentials. Error: " + str(error)
        )
        exit(1)


def move_backup_files():
    """Move backup files to remote location."""
    print_with_color(
        f"{Color.BOLD}Sending data to another VM...",
        Color.YELLOW
    )

    try:
        remote_location = f"{remote_user}@{remote_host}:{remote_ce_dir}"
        scp_command = ["scp"] + ssh_auth + [backup_zip, remote_location]
        output, success = run_ssh_scp(
            "scp",
            remote_password,
            *scp_command,
            print_output=False
        )
        if not success:
            print_warning(
                "Unable to connect with SSH credentials. "
                "Got: {}\nExiting...".format(
                    output
                )
            )
            exit(1)
        print_with_color(
            f"{Color.BOLD}Data sent to the destination VM successfully.",
            Color.YELLOW
        )

        print_with_color(
            f"{Color.BOLD}Unzipping backup on the destination VM...",
            Color.YELLOW
        )
        ssh_command = (
            ["ssh"]
            + ssh_auth
            + [
                f"{remote_user}@{remote_host}",
                f"sudo unzip -o {remote_ce_dir}/{backup_zip}"
                f" -d {remote_ce_dir}",
            ]
        )
        output, success = run_ssh_scp(
            "ssh",
            remote_password,
            *ssh_command,
            print_output=False
        )
        if not success:
            print_warning(
                "Unable to unzip backup on the destination VM. "
                "Got: {}\nExiting...".format(
                    output
                )
            )
            exit(1)
        print_pass(
            "Backup unzipped successfully on the destination VM.",
        )
    except Exception as error:
        print_fail(
            "Failed to send data to the destination VM. Error: " + str(error)
        )
        exit(1)


def check_rabbitmq_size():
    """Check RabbitMQ size."""
    try:
        global envs
        if not envs:
            print_fail("Could not load environment variables. Exiting...")
            exit(1)
        HA_IP_LIST = envs.get("HA_IP_LIST", "")
        if isRedHat79():
            compose_command = ["docker", "compose"]
            if HA_IP_LIST:
                compose_command.extend(["-f", "docker-compose-ha.yml"])
            else:
                compose_command.extend(["-f", "docker-compose.yml"])
        elif isRedHat():
            compose_command = ["podman-compose"]
            if HA_IP_LIST:
                compose_command.extend(["-f", "podman-compose-ha.yml"])
            else:
                compose_command.extend(["-f", "podman-compose.yml"])
        else:
            compose_command = ["docker", "compose"]
            if HA_IP_LIST:
                compose_command.extend(["-f", "docker-compose-ha.yml"])
            else:
                compose_command.extend(["-f", "docker-compose.yml"])
        print_with_color(
            f"{Color.BOLD}Checking the size of the RabbitMQ data directory...",
            Color.YELLOW
        )
        output = subprocess.run(
            ["du", "-sh", "./data/rabbitmq/data"], check=True,
            capture_output=True
        )
        matched = re.match(r"^(\d+(\.\d+)?)([KMG])", output.stdout.decode())
        if not matched:
            raise ValueError(
                "Failed to calculate the size of the RabbitMQ data directory."
            )
        size = matched.group(1)
        unit = matched.group(3)
        continue_the_script = False
        if unit == "K":
            size = float(size) / 1024
        elif unit == "M":
            size = float(size[:-1])
        elif unit == "G":
            size = float(size[:-1]) * 1024 * 1024
        else:
            raise ValueError("Unknown unit: " + unit)
        if size >= 250:
            print_with_color(
                "\n"
                f"The size of the RabbitMQ data directory is "
                f"{matched.group(1)}{matched.group(2)}.\n"
                "The recommended size is around 200M after disabling all the "
                "plugins. If you have not disabled all the plugins, please "
                "disable them first and then run this script again.\n"
                "If you're proceeding now, make sure you have free space "
                f"{Color.UNDERLINE}at least twice{Color.END} the current "
                "size.\n",
                Color.BOLD
            )
            continue_the_script = input(
                f"{Color.BOLD}Do you want to continue? (y/n) "
                f"[default is \"No\"]: {Color.END}"
            ).strip()
            if continue_the_script.lower() not in ["y", "yes"]:
                print_warning("Exiting...")
                exit(1)
            else:
                print_pass("Continuing as preferred...")
                continue_the_script = True
        else:
            print_pass("The size of the RabbitMQ data directory is OK.")
        print_with_color(
            f"{Color.BOLD}Checking the number of messages in the "
            "RabbitMQ queue...",
            Color.YELLOW
        )
        output = subprocess.run(
            compose_command + [
                "exec", "rabbitmq-stats", "rabbitmqctl", "list_queues"
            ],
            check=True,
            capture_output=True,
        )
        queues = output.stdout.decode().split("\n")
        in_queue = 0
        for queue in queues:
            matched = re.match(r"^(.+)\s(\d)$", queue)
            if matched:
                in_queue += int(matched.group(2))
        if in_queue > 50:
            if continue_the_script:
                print_warning(
                    "The number of messages in the RabbitMQ queue are "
                    f"{in_queue}. Recommended size is around 50.\n"
                    "Continuing as preferred..."
                )
            else:
                continue_the_script = input(
                    f"\n{Color.BOLD}"
                    "The number of messages in the RabbitMQ queue are "
                    f"{in_queue}. Recommended size is around 50.\n"
                    f"Do you want to continue? (y/n) "
                    f"[default is \"No\"]: {Color.END}"
                ).strip()
                if continue_the_script.lower() not in ["y", "yes"]:
                    print_warning("Exiting...")
                    exit(1)
                else:
                    print_pass("Continuing as preferred...")
        else:
            print_pass("The number of messages in the RabbitMQ queue is OK.")
    except Exception as error:
        print_fail(
            "Failed to check the RabbitMQ size or number of messages"
            ". Check if containers are running. Got Error: " + str(error)
        )
        exit(1)


def move_files_to_shared_drive_path():
    """Get the shared drive path."""
    print_with_color(
        "Please enter the path to the mounted shared drive on the destination "
        "machine. Which will be used in the HA deployment as a shared "
        "storage.",
        Color.BOLD
    )
    global shared_drive_path
    try:
        tried = 0
        while not shared_drive_path and tried < 3:
            shared_drive_path = input("Enter the path here{}: ".format(
                f" ({3-tried} out of 3 tries remaining)"
                if tried > 0 else ""
            )).strip().rstrip("/")
            ssh_command = (
                ["ssh"]
                + ssh_auth
                + [
                    f"{remote_user}@{remote_host}",
                    f"[ -d {shared_drive_path} ] && echo true || echo false",
                ]
            )
            output, success = run_ssh_scp(
                "ssh",
                remote_password,
                *ssh_command,
                print_output=False
            )
            if not success:
                print_warning(
                    "Unable to connect with SSH credentials. "
                    "Got: {}\nExiting...".format(
                        output
                    )
                )
                exit(1)
            if output == "false":
                print_warning(
                    f"{shared_drive_path} does not exist on the "
                    "destination machine."
                )
                shared_drive_path = None
            tried += 1
        if not shared_drive_path:
            raise ValueError(
                "Invalid path provided after 3 tries. Exiting..."
            )
        print_with_color(
            f"{Color.BOLD}Moving files to the shared drive...",
            Color.YELLOW
        )
        ssh_command = (
            ["ssh"]
            + ssh_auth
            + [
                f"{remote_user}@{remote_host}",
                f"sudo cp -r {remote_ce_dir}/data/custom_plugins"
                f" {shared_drive_path}/custom_plugins",
            ]
        )
        output, success = run_ssh_scp(
            "ssh",
            remote_password,
            *ssh_command,
            print_output=False
        )
        if not success:
            print_warning(
                "Unable to copy files to the shared drive. "
                "Got: {}\nExiting...".format(output)
            )
            exit(1)
        print_pass(
            "Custom plugins copied to the shared drive successfully."
        )
    except Exception as error:
        print_fail(
            "Failed to move files to the shared drive. Error: "
            + str(error)
        )
        exit(1)


def grab_maintainance_password():
    """Grab the maintainance password from the .env or .env.keys file."""
    print_with_color(
        f"{Color.BOLD}Grabbing the maintainance password...",
        Color.YELLOW
    )
    global maintenance_password
    try:
        global envs
        if os.path.exists(".env.keys"):
            with open(".env.keys", "r") as f:
                pwds = {
                    line.split("=")[0].strip(): line.split("=")[1].strip()
                    for line in f.readlines()
                    if line and line.split("=")
                }
                maintenance_password = pwds["MAINTENANCE_PASSWORD"]
                os.environ["MAINTENANCE_PASSWORD"] = pwds[
                    "MAINTENANCE_PASSWORD"
                ]
                os.environ["MAINTENANCE_PASSWORD_ESCAPED"] = pwds[
                    "MAINTENANCE_PASSWORD_ESCAPED"
                ]
                print_pass("Maintainance password grabbed successfully.")
        elif envs.get("MAINTENANCE_PASSWORD"):
            maintenance_password = envs["MAINTENANCE_PASSWORD"]
            print_pass("Maintainance password grabbed successfully.")
        else:
            raise ValueError(
                "Failed to grab the maintainance password as"
                " no .env or .env.keys files exist."
            )
    except Exception as error:
        print_fail(
            "Failed to grab the maintainance password. Error: "
            + str(error)
        )
        exit(1)


def set_to_ce_as_vm_dest():
    """Set the destination to the CE."""
    global remote_ce_dir
    global ce_as_a_vm_dest
    remote_ce_dir = os.path.join(
        "/opt",
        "cloudexchange",
        "cloudexchange"
    )
    ce_as_a_vm_dest = True


def print_next_steps():
    """Print the next steps."""
    print_pass("All done. Now you can run the next steps manually.")
    for step in remaining_steps[int(option)]:
        print_with_color(step, Color.PURPLE)


def print_maintenance_password():
    """Print the maintenance password."""
    print_with_color(
        f"{Color.BOLD}The maintenance password is: "
        f"{Color.UNDERLINE}{Color.BOLD}{maintenance_password}{Color.END}\n"
        f"{Color.DARKCYAN}Make sure to enter the above password "
        "in the next steps.",
        Color.DARKCYAN
    )


def reset_files():
    """Reset the files."""
    print_with_color(
        "Resetting files...",
        Color.YELLOW
    )
    try:
        if os.path.exists(backup_zip):
            print_with_color(
                "Deleting backup files...",
                Color.YELLOW
            )
            os.remove(backup_zip)
            print_pass("Backup files deleted successfully.")
    except Exception as error:
        print_fail("Failed to delete backup files. Error: " + str(error))
        exit(1)


def on_exit(*args, **kwargs):
    """On exit."""
    message = (
        "\nExiting the migration or upgrade process, we might have stopped "
        "all the running service, "
        "\nPlease make sure to up all the services "
        "before retrying the process or using services again.\n"
        f"Start the services with: {Color.BOLD}{Color.UNDERLINE}sudo ./start\n"
    )
    print_with_color(message, Color.RED)


class Steps(Enum):
    """Steps Enum."""

    STOP = "stop"
    RESET = "reset"
    CHECK_RABBITMQ_SIZE = "remote_check_rabbitmq_size"
    GET_LOCAL_DATA_FOLDER = "get_local_data_folder"
    BACKUP_RABBITMQ_AND_MONGO = "backup_rabbitmq_and_mongo"
    BACKUP_CUSTOM_PLUGINS = "backup_custom_plugins"
    BACKUP_REPOS = "backup_repos"
    BACKUP_PLUGIN = "backup_plugin"
    MOVE_BACKUP_FILES = "move_backup_files"
    MOVE_FILES_TO_SHARED_DRIVE = "move_files_to_shared_drive"
    GRAB_MAINTENANCE_PASSWORD = "grab_maintenance_password"
    REMOTE_RESTORE_HA_BACKUP = "restore_ha_backup"
    GET_SSH_CREDENTIALS = "get_ssh_credentials"
    SET_TO_CE_AS_VM_DEST = "set_to_ce_as_vm_dest"
    PRINT_NEXT_STEPS = "print_next_steps"
    PRINT_MAINTENANCE_PASSWORD = "print_maintenance_password"
    RESET_FILES = "reset_files"


steps_method_mapping = {
    Steps.STOP: stop,
    Steps.RESET: reset,
    Steps.BACKUP_RABBITMQ_AND_MONGO: lambda: backup(
        Steps.BACKUP_RABBITMQ_AND_MONGO
    ),
    Steps.BACKUP_CUSTOM_PLUGINS: lambda: backup(Steps.BACKUP_CUSTOM_PLUGINS),
    Steps.BACKUP_REPOS: lambda: backup(Steps.BACKUP_REPOS),
    Steps.BACKUP_PLUGIN: lambda: backup(Steps.BACKUP_PLUGIN),
    Steps.MOVE_BACKUP_FILES: move_backup_files,
    Steps.GET_SSH_CREDENTIALS: get_ssh_credentials,
    Steps.CHECK_RABBITMQ_SIZE: check_rabbitmq_size,
    Steps.MOVE_FILES_TO_SHARED_DRIVE: move_files_to_shared_drive_path,
    Steps.GRAB_MAINTENANCE_PASSWORD: grab_maintainance_password,
    Steps.SET_TO_CE_AS_VM_DEST: set_to_ce_as_vm_dest,
    Steps.PRINT_NEXT_STEPS: print_next_steps,
    Steps.PRINT_MAINTENANCE_PASSWORD: print_maintenance_password,
    Steps.RESET_FILES: reset_files,
}

remaining_steps = {
    1: [
        f"Run: {Color.BOLD}sudo ./setup",
        f"Start the Cloud Exchange with: {Color.BOLD}sudo ./start"
    ],
    2: [
        "Run the setup script in the primary node first and update the IP list"
        ". Keep the existing IPs in the same order and add a new IP "
        f"address at the end.\nWith:{Color.BOLD} sudo python3 ./setup",
        "Run the setup script in the remaining machines to add the connection "
        f"info.\nWith: {Color.BOLD}sudo python3 ./setup --location "
        "/path/to/mounted/directory",
        "Run the start script in the primary node first and then run the start"
        " script for remaining machines as well. At last run the start script "
        f"in the new node.\nWith: {Color.BOLD}sudo ./start"
    ],
    3: [
        "Run the setup script in the primary node first using the below "
        f"command:\n{Color.BOLD}sudo python3 ./setup",
        "Next run the below commands in secondary and third nodes."
        f"\n{Color.BOLD}sudo python3 ./setup --location <shared_drive>",
        "Migrate RabbitMQ and Mongo data, run the following command one time"
        f" only on primary node.\n{Color.BOLD}sudo MIGRATE_MONGO=false ./restore_ha_backup",
        "Start the containers, beginning with the primary node followed"
        f" by the other nodes, using\n{Color.BOLD}sudo ./start",
    ],
    4: [
        "Make sure Cloud Exchange is not started yet. If it was started,"
        f" stop it using this command.\n{Color.BOLD}sudo ./stop",
        "Execute the setup script and follow the steps."
        f"\n{Color.BOLD}sudo ./setup",
        "Make sure you enter the same maintenance password as populated "
        "here while migrating.",
        "Launch Cloud Exchange.\nsudo ./start"
    ],
    5: [
        "Make sure Cloud Exchange is not started yet. If it was started,"
        " stop it using this command.\nsudo ./stop",
        "Execute the setup script and follow the steps.\nsudo ./setup",
        "Make sure you enter the same maintenance password as populated "
        "here while migrating.",
        "Launch Cloud Exchange.\nsudo ./start"
    ],
    6: [
        "Run the setup script in the primary node first using this "
        "command.\nsudo python3 ./setup",
        "Make sure you enter the same maintenance password as populated "
        "here while migrating.",
        "Then run the below commands in secondary and third nodes.\n"
        "sudo python3 ./setup --location <shared_drive>",
        "Migrate RabbitMQ and Mongo data, run the following command one time"
        " only on primary node.\nsudo ./restore_ha_backup",
        "Start the containers, beginning with the Primary node followed by the"
        " other nodes, using this command.\nsudo ./start"
    ],
    7: [
        "Run the setup script in the primary node first using this command."
        "\nsudo ./setup",
        "Make sure you enter the same maintenance password as populated "
        "here while migrating.",
        "Next run this command in the secondary and third nodes."
        "\nsudo ./setup --location <shared_drive>",
        "To migrate the RabbitMQ and Mongo data, use this command one time"
        " only on the primary node.\nsudo ./restore_ha_backup",
        "Start the containers, beginning with the Primary node followed by the"
        " other nodes, using this command.\nsudo ./start"
    ]
}


options_steps_mapping = {
    1: [
        Steps.STOP,
        Steps.RESET,
    ],
    2: [
        Steps.CHECK_RABBITMQ_SIZE,
        Steps.STOP,
        Steps.RESET,
    ],
    3: [
        Steps.CHECK_RABBITMQ_SIZE,
        Steps.STOP,
        Steps.RESET_FILES,
        Steps.BACKUP_RABBITMQ_AND_MONGO,
        Steps.BACKUP_CUSTOM_PLUGINS,
        Steps.GET_SSH_CREDENTIALS,
        Steps.MOVE_BACKUP_FILES,
        Steps.MOVE_FILES_TO_SHARED_DRIVE,
    ],
    4: [
        Steps.STOP,
        Steps.GRAB_MAINTENANCE_PASSWORD,
        Steps.RESET_FILES,
        Steps.BACKUP_RABBITMQ_AND_MONGO,
        Steps.BACKUP_CUSTOM_PLUGINS,
        Steps.SET_TO_CE_AS_VM_DEST,
        Steps.GET_SSH_CREDENTIALS,
        Steps.MOVE_BACKUP_FILES,
        Steps.PRINT_MAINTENANCE_PASSWORD,
    ],
    5: [
        Steps.STOP,
        Steps.GRAB_MAINTENANCE_PASSWORD,
        Steps.RESET_FILES,
        Steps.BACKUP_RABBITMQ_AND_MONGO,
        Steps.BACKUP_REPOS,
        Steps.BACKUP_PLUGIN,
        Steps.BACKUP_CUSTOM_PLUGINS,
        Steps.SET_TO_CE_AS_VM_DEST,
        Steps.GET_SSH_CREDENTIALS,
        Steps.MOVE_BACKUP_FILES,
        Steps.PRINT_MAINTENANCE_PASSWORD,
    ],
    6: [
        Steps.CHECK_RABBITMQ_SIZE,
        Steps.STOP,
        Steps.GRAB_MAINTENANCE_PASSWORD,
        Steps.RESET_FILES,
        Steps.BACKUP_RABBITMQ_AND_MONGO,
        Steps.BACKUP_REPOS,
        Steps.BACKUP_PLUGIN,
        Steps.BACKUP_CUSTOM_PLUGINS,
        Steps.SET_TO_CE_AS_VM_DEST,
        Steps.GET_SSH_CREDENTIALS,
        Steps.MOVE_BACKUP_FILES,
        Steps.MOVE_FILES_TO_SHARED_DRIVE,
        Steps.PRINT_MAINTENANCE_PASSWORD,
    ],
    7: [
        Steps.CHECK_RABBITMQ_SIZE,
        Steps.STOP,
        Steps.GRAB_MAINTENANCE_PASSWORD,
        Steps.RESET_FILES,
        Steps.BACKUP_RABBITMQ_AND_MONGO,
        Steps.BACKUP_REPOS,
        Steps.BACKUP_PLUGIN,
        Steps.BACKUP_CUSTOM_PLUGINS,
        Steps.SET_TO_CE_AS_VM_DEST,
        Steps.GET_SSH_CREDENTIALS,
        Steps.MOVE_BACKUP_FILES,
        Steps.MOVE_FILES_TO_SHARED_DRIVE,
        Steps.PRINT_MAINTENANCE_PASSWORD,
    ],
}

if __name__ == "__main__":
    atexit.register(on_exit)
    message = (
        f"{Color.RED}{Color.BOLD}Note:- If you are proceeding for the "
        "Standalone to HA or HA to HA migration, Please make sure "
        "\n\t\tthat the shared drive is mounted on the destination machine"
        " which will be used in the HA and\n\t\t make sure all the services"
        " are up and running. Currently we do not support "
        f"HA to Standalone migration.{Color.END}"
    )
    print_with_color(
        f"""
        {Color.GREEN}{Color.BOLD}Welcome! to Cloud Exchange Upgrade/Migration Tool.

        {message}

        {Color.BOLD}Select the option:
            1. Upgrade Existing Standalone (Ubuntu/RHEL) to 5.1.0 from 4.2.0 or 5.0.x
            2. Upgrade Existing HA (Ubuntu/RHEL) to 5.1.0 from 4.2.0 or 5.0.x
            3. Upgrade to HA (Ubuntu/RHEL) 5.1.0 from Standalone (Ubuntu/RHEL) 4.2.0 or 5.0.x
            4. Migrate to CE as VM (AWS/Azure/VMware) 5.1.0 from 4.2.0 Standalone (Ubuntu/RHEL)
            5. Migrate to CE as VM (AWS/Azure/VMware) 5.1.0 from 5.0.0 or 5.0.1 Standalone (Ubuntu/RHEL)
            6. Migrate to CE as VM (AWS/Azure/VMware) 5.1.0 HA from 5.0.0 or 5.0.1 Standalone (Ubuntu/RHEL)
            7. Migrate to CE as VM (AWS/Azure/VMware) 5.1.0 HA from 5.0.0 or 5.0.1 HA (Ubuntu/RHEL)
        """,
        Color.BOLD
    )
    try:
        option = input("Enter the option number: ").strip()
        if option not in [str(i) for i in list(range(1, 8))]:
            print_fail("Invalid option.")
            exit(1)
        load_env()
        for step in (
            options_steps_mapping[int(option)]
            + [Steps.PRINT_NEXT_STEPS]
        ):
            steps_method_mapping[step]()
    except KeyboardInterrupt:
        exit(1)
    atexit.unregister(on_exit)
