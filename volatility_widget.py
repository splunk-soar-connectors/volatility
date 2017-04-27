# --
# File: volatility_widget.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

from phantom.vault import Vault


def malfind(provides, all_results, context):
  context['buffers'] = buffers = []
  for summary, command_results in all_results:
    for result in command_results:
      buffers.extend(result.get_data())

  return 'malfind.html'


def download(provides, all_results, context):
  try:
    context['files'] = files = []
    for summary, command_results in all_results:
      for result in command_results:
        data = result.get_data()
        if data:
          fileinfo = data[0]
          fileinfo['path'] = Vault.get_file_path(fileinfo['vault_id'])
          files.append(fileinfo)
  except:
    context['files'] = []

  context['title1'] = provides
  return 'download_from_vault.html'
