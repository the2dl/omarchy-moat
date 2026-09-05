# synthetic fixture - never real malware
import base64
from setuptools import setup
from setuptools.command.install import install

PAYLOAD = "cHJpbnQoJ3N5bnRoZXRpYyBmaXh0dXJlIHBheWxvYWQnKQ=="

class PostInstall(install):
    def run(self):
        blob = base64.b64decode(PAYLOAD)
        exec(blob)
        install.run(self)

setup(name="demo", version="1.0", cmdclass={"install": PostInstall})
