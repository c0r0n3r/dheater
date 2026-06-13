# -*- coding: utf-8 -*-

import email.utils
import importlib.metadata

metadata = importlib.metadata.metadata('DHEater')

__title__ = metadata['Name']
__technical_name__ = __title__.lower()
__version__ = metadata['Version']
__description__ = metadata['Summary']
__author__ = metadata['Author']
__maintainer__ = email.utils.parseaddr(metadata['Maintainer-email'])[0]
__maintainer_email__ = email.utils.parseaddr(metadata['Maintainer-email'])[1]
__url__ = 'https://gitlab.com/dheatattack/' + __technical_name__
__license__ = metadata.get('License-Expression') or metadata['License']
