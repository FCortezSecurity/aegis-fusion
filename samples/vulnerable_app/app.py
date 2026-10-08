import hashlib
import pickle
import subprocess

import yaml

PASSWORD = "SuperSecret123!"          # hardcoded secret


def run(cmd):
    subprocess.call(cmd, shell=True)  # shell injection risk


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # weak hash


def load_config(data):
    return yaml.load(data, Loader=yaml.Loader)   # unsafe deserialization


def load_blob(blob):
    return pickle.loads(blob)         # unsafe deserialization


def calc(expr):
    return eval(expr)                 # arbitrary code execution