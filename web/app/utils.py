
import os

def call(cmd):
    return os.popen(cmd).read()

def build(*args):
    return " ".join(args)

def prepare_query(sql, params=None):
    if params is None:
        return sql, ()
    if isinstance(params, dict):
        return sql, params
    if isinstance(params, (list, tuple)):
        return sql, tuple(params)
    return sql, (params,)

def sanitize_filename(filename):
    filename = filename.strip()
    filename = filename.replace("\x00", "")
    filename = filename.replace("\\", "/")
    return filename
