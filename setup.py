# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name="taxa-sdk",
    version='0.1.1',
    description='Developer SDK for the Taxa Network',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    author='TF Guo',
    author_email='tf@taxa.network',
    url='https://github.com/taxa-network/SDK-Python',
    packages=find_packages(),
    #scripts=['bin/'],
    include_package_data=True,
    license='LICENSE',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
    ],
    install_requires=['pyaes', 'requests', 'base58==1.0.3']
)
