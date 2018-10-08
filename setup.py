from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="cp_mgmt_api_python_sdk",
    version="0.0.1",
    author="Check Point",
    author_email="author@checkpoint.com",
    description="Check Point R80.10 Management API SDK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CheckPointSW/cp_mgmt_api_python_sdk",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: Apache License",
        "Operating System :: OS Independent",
    ],
)
