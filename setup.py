"""Setup script for CHIRP."""

# Standard Python Libraries
import sys

# Third-Party Libraries
from setuptools import setup


def _get_platform():
    if sys.platform == "darwin":
        return "MacOS"
    elif "win" in sys.platform:
        return "Windows"
    elif sys.platform == "linux":
        return "Linux"
    else:
        return "UNSUPPORTED"


OS = _get_platform()
REQ = None

if OS == "Windows":
    REQ = [
        "nuitka",
        "python-evtx",
        "yara-python",
        "rich",
        "pyyaml",
        "psutil",
        "xmljson",
        "aiomultiprocess",
    ]
elif OS in ["Linux", "MacOS"]:
    REQ = ["nuitka", "yara-python", "rich", "pyyaml", "psutil", "aiomultiprocess"]
else:
    raise OSError(
        "The operating system {} is not supported by chirp.".format(sys.platform)
    )

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="chirp",
    version="1.0",
    author="William Deem",
    description="A forensic analysis tool to rapidly locate indicators of compromise.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cisagov/chirp",
    project_urls={"Bug Tracker": "https://github.com/cisagov/chirp/issues"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Natural Language :: English",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Internet :: Log Analysis",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Security",
        "Topic :: Utilities",
        "Typing :: Typed",
    ],
    packages=[
        "chirp",
        "chirp.plugins",
        "chirp.plugins.events",
        "chirp.plugins.registry",
        "chirp.plugins.yara",
        "chirp.plugins.network",
    ],
    install_requires=REQ,
    python_requires=">=3.6",
)
