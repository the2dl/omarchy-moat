import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ordinary-lib",
    version="1.2.3",
    packages=find_packages(exclude=["tests"]),
    long_description=long_description,
    install_requires=["requests>=2.28", "click>=8"],
    entry_points={"console_scripts": ["ordinary = ordinary_lib.cli:main"]},
)
