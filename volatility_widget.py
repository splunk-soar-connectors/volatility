# File: volatility_widget.py
#
# Copyright (c) 2014-2016 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
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
