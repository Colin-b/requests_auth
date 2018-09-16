import os
from setuptools import setup, find_packages
from requests_auth import _version

this_dir = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_dir, 'README.rst'), 'r') as f:
    long_description = f.read()

# More information on properties: https://packaging.python.org/distributing
setup(name='requests_auth',
      version=_version.__version__,
      author='Colin Bounouar',
      maintainer='Colin Bounouar',
      url="https://github.com/Colin-b/requests_auth",
      description="Easy Authentication for Requests",
      long_description=long_description,
      download_url='https://pypi.python.org/pypi/requests-auth',
      license='MIT',
      classifiers=[
          "Development Status :: 5 - Production/Stable",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: MIT License",
          "Natural Language :: English",
          "Programming Language :: Python",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Topic :: Software Development :: Build Tools",
      ],
      keywords=[
          'authentication',
          'ntlm',
          'oauth2',
          'apikey',
          'multiple',
      ],
      packages=find_packages(exclude=['tests']),
      tests_require=[
          # Used to run tests
          'nose==1.3.7',
          # Used to generate a JWT token
          'pyjwt==1.6.4',
          # Used to run test services
          'flask==1.0.2',
      ],
      install_requires=[
          # Used for Base Authentication and to communicate with OAuth2 servers (also used in test cases)
          'requests==2.19.1',
      ],
      platforms=[
          'Windows',
          'Linux',
      ],
      )
