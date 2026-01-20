from setuptools import setup, find_packages

setup(
    name="easylic",
    version="0.0.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "pydantic",
        "cryptography",
        "requests",
        "click",
    ],
    entry_points={
        "console_scripts": [
            "easylic=easylic.cli:cli",
        ],
    },
)