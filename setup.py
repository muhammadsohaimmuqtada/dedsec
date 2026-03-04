from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="dedsec",
    version="1.0.0",
    author="Sohaim",
    description="DEDSEC — Advanced Web Reconnaissance Framework",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "dedsec = dedsec.cli:main",
        ],
    },
    python_requires=">=3.8",
)
