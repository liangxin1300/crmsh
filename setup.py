#!/usr/bin/env python3
# Note that this script only installs the python modules,
# the other parts of crmsh are installed by autotools
from setuptools import setup

setup(name='crmsh_boot',
      version='0.6.1',
      description='Command-line interface to bootstrap cluster',
      author='Kristoffer Gronlund; Xin Liang',
      author_email='XLiang@suse.com',
      url='http://crmsh.github.io/',
      packages=['crmsh'],
      install_requires=['ClusterAPI', 'lxml'],
      scripts=['bin/crm'],
      data_files=[('/usr/share/crmsh', ['doc/crm.8.adoc'])],
      include_package_data=True)
