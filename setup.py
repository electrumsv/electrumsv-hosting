from typing import List

import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="electrumsv-hosting",
    version="0.1.3",
    author="Roger Taylor",
    author_email="roger.taylor.email@gmail.com",
    description="Supporting code for ElectrumSV wallets to communicate using encrypted connections",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/electrumsv/electrumsv-hosting",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries',
        'Topic :: Security :: Cryptography',
    ],
    python_requires='>=3.6',
)
