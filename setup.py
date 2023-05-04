#!/usr/bin/env python
# -*- coding: utf-8 -*-

import codecs
import os
import unittest

from setuptools import setup

from dheater import __setup__


this_directory = os.getenv('REQUIREMENTS_DIR', '')
with open(os.path.join(this_directory, 'requirements.txt')) as f:
    install_requirements = f.read().splitlines()
this_directory = os.path.abspath(os.path.dirname(__file__))
with codecs.open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


test_requirements = [
    "unittest2",
    "coverage",
    "six",
]


def test_discover():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('test', pattern='test_*.py')
    return test_suite


setup(
    name=__setup__.__title__,
    version=__setup__.__version__,
    description=__setup__.__description__,
    long_description=long_description,
    long_description_content_type='text/markdown',
    author=__setup__.__author__,
    maintainer=__setup__.__maintainer__,
    maintainer_email=__setup__.__maintainer_email__,
    license=__setup__.__license__,
    license_files=['LICENSE.txt', ],
    keywords='dhe denial-of-service tls ssh',
    url=__setup__.__url__,
    entry_points={
        'console_scripts': ['dheat = dheater.__main__:main']
    },
    install_requires=install_requirements,
    extras_require={
        "test": test_requirements,
        "pep8": ["flake8", ],
        "pylint": ["pylint", ],
    },

    packages=[
        'dheater',
    ],

    scripts = ['tools/dh_param_priv_key_size_setter'],

    test_suite='setup.test_discover',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Testing :: Traffic Generation',
        'Topic :: Software Development :: Testing',
    ],
)
