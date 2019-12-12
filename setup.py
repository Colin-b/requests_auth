import os
from setuptools import setup, find_packages

this_dir = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_dir, "README.md"), "r") as f:
    long_description = f.read()

# More information on properties: https://packaging.python.org/distributing
setup(
    name="requests_auth",
    version=open("requests_auth/version.py").readlines()[-1].split()[-1].strip("\"'"),
    author="Colin Bounouar",
    author_email="colin.bounouar.dev@gmail.com",
    maintainer="Colin Bounouar",
    maintainer_email="colin.bounouar.dev@gmail.com",
    url="https://colin-b.github.io/requests_auth/",
    description="Authentication for Requests",
    long_description=long_description,
    long_description_content_type="text/markdown",
    download_url="https://pypi.org/project/requests-auth/",
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Build Tools",
    ],
    keywords=[
        "authentication",
        "ntlm",
        "oauth2",
        "azure-active-directory",
        "azure-ad",
        "okta",
        "apikey",
        "multiple",
    ],
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        # Used for Base Authentication and to communicate with OAuth2 servers
        "requests==2.*"
    ],
    extras_require={
        "testing": [
            # Used to generate test tokens
            "pyjwt==1.*",
            # Used to mock responses to requests
            "pytest-responses==0.4.*",
            # Used to check coverage
            "pytest-cov==2.*",
        ]
    },
    python_requires=">=3.6",
    project_urls={
        "GitHub": "https://github.com/Colin-b/requests_auth",
        "Changelog": "https://github.com/Colin-b/requests_auth/blob/master/CHANGELOG.md",
        "Issues": "https://github.com/Colin-b/requests_auth/issues",
    },
    platforms=["Windows", "Linux"],
)
