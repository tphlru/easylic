from setuptools import find_packages, setup

setup(
    name="easylic",
    version="0.0.0",
    packages=find_packages(),
    include_package_data=True,
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
