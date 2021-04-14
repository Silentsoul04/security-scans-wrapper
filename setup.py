#! /usr/bin/env python3
from setuptools import setup, find_packages
import pathlib

setup(
    name                =   "security-scans-wrapper",
    description         =   "This is a simple wrapper for scripts that runs on a given URL.",
    url                 =   "https://github.com/tristanlatr/security-scans-wrapper",
    author              =   "tristanlatr",
    version             =   "2.dev0",
    py_modules          =   ['security_scans_wrapper',],
    classifiers         =   ["Programming Language :: Python :: 3"],
    license             =   "MIT License",
    long_description    =   pathlib.Path(__file__).parent.joinpath("README.md").read_text(),
    long_description_content_type   =   "text/markdown",
    install_requires    =   [
            "attrs",
            "markdown",
            "pymdown-extensions",
            "ansi2html",
            "invoke",
    ],
)
