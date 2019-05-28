import setuptools
from setuptools import setup

setup(
    name="cpapi",
    version="1.0.3",
    author="API team",
    author_email="api_team@checkpoint.com",
    description="Check Point Management API SDK",
    long_description="Check Point API Python Development Kit simplifies the usage of the Check Point Management APIs. "
                     "The kit contains the API library project, "
                     "and sample projects demonstrating the capabilities of the library. "
                     "The kit is python 2 and 3 compatible code.",
    long_description_content_type="text",
    url="https://github.com/CheckPointSW/cp_mgmt_api_python_sdk.git",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache License",
        "Operating System :: OS Independent",
    ],

)