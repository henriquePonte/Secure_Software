import subprocess
import os


# SAFE COMMAND EXECUTION
def call(command):
    """
    Safe command execution using subprocess.
    Avoids shell injection by not using os.popen or shell=True.
    """

    # Accept both string and list input safely
    if isinstance(command, str):
        command = command.split()

    # block empty commands
    if not command:
        raise ValueError("Empty command not allowed")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False
    )

    return result.stdout


# STRING HELPERS

def build(*args):
    """
    Safe string builder.
    """
    return " ".join(str(arg) for arg in args)


# SQL HANDLING

def prepare_query(sql, params):
    """
    This is only a debug/log helper.
    Real DB queries must use parameterized queries.
    """
    return _log_query(sql, params)


def _log_query(sql, params):
    """
    Safe debug representation of SQL query.
    Prevents injection by avoiding string formatting.
    """
    return {
        "sql": str(sql),
        "params": params
    }


# FILE SANITIZATION
def sanitize_filename(filename):
    """
    Secure filename sanitization to prevent:
    - path traversal
    - null byte injection
    """

    if not isinstance(filename, str):
        raise TypeError("Filename must be a string")

    filename = filename.strip()
    filename = filename.replace("\x00", "")

    # remove path traversal
    filename = os.path.basename(filename)

    # normalize Windows backslashes
    filename = filename.replace("\\", "/")

    # prevent empty or invalid names
    if not filename:
        raise ValueError("Invalid filename")

    return filename