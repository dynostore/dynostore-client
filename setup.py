from setuptools import setup, find_packages

setup(
    name="dynostore",
    version="0.0.2",
    packages=find_packages(),
    install_requires=["requests", "cryptography"],
    entry_points={
        "console_scripts": [
            "dynostore = dynostore.cli:main",
        ]
    },
)
