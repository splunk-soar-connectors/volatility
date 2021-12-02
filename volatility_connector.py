# File: volatility_connector.py
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
#
#
# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from phantom.vault import Vault

# THIS Connector imports
from volatility_consts import *

import uuid
import os
import glob
import re
import shutil
import sys
import fnmatch

# Volatility imports
# pylint: disable=E0611
import volatility.conf as vol_conf
import volatility.registry as registry
import volatility.commands as vol_commands
import volatility.addrspace as addrspace
# import volatility.plugins.filescan as filescan
import volatility.plugins.vadinfo as vadinfo
import volatility.utils as vol_utils
import volatility.plugins.malware.malfind as malfind
import volatility.protos as protos

# Code to execute inorder to use volatility as a library
# TODO: Move these to initialize()
registry.PluginImporter()
vol_config = vol_conf.ConfObject()
registry.register_global_options(vol_config, vol_commands.Command)
registry.register_global_options(vol_config, addrspace.BaseAddressSpace)
cmds = registry.get_plugin_classes(vol_commands.Command, lower=True)

# the following argv 'work around' is to keep volatility happe
# and _also_ debug the connector as a script via pudb
try:
    argv_temp = list(sys.argv)
except:
    pass
sys.argv = ['']
vol_config.parse_options()


class VolatilityConnector(BaseConnector):

    ACTION_ID_GET_PSINFO = "get_psinfo"
    ACTION_ID_EXTRACT_PROCESS = "get_process_image"
    ACTION_ID_RUN_EXHAUSTIVE_CMDS = "run_exhaustive_commands"
    ACTION_ID_RUN_DRIVERSCAN = "run_driverscan"
    ACTION_ID_RUN_MUTANTSCAN = "run_mutantscan"
    ACTION_ID_RUN_FILESCAN = "run_filescan"
    ACTION_ID_RUN_HIVELIST = "run_hivelist"
    ACTION_ID_RUN_MALFIND = "run_malfind"
    ACTION_ID_RUN_SHELLBAGS = "run_shellbags"
    ACTION_ID_RUN_TIMELINER = "run_timeliner"
    ACTION_ID_RUN_CMDSCAN = "run_cmdscan"
    ACTION_ID_RUN_PRINTKEY = "run_printkey"
    ACTION_ID_RUN_MFTPARSER = "run_mftparser"
    ACTION_ID_RUN_SOCKSCAN = "run_sockscan"
    ACTION_ID_RUN_IEHISTORY = "run_iehistory"
    ACTION_ID_LIST_CONNECTIONS = "list_connections"

    def __init__(self):

        # Call the BaseConnectors init first
        super(VolatilityConnector, self).__init__()

    def initialize(self):
        return self._get_vol_py_path(self)

    def _get_vol_py_path(self, result):

        app_dir = os.path.dirname(os.path.abspath(__file__))

        matches = []
        for root, dirnames, filenames in os.walk("{0}/dependencies".format(app_dir)):
            for filename in fnmatch.filter(filenames, 'vol.py'):
                matches.append(os.path.join(root, filename))

        if (not matches):
            return result.set_status(phantom.APP_ERROR, "Unable to find vol.py in app directory")

        # The first instance that matches is good
        self._vol_py_path = matches[0]

        return (phantom.APP_SUCCESS)

    def _get_profile(self, vol_config, cmds, action_result):

        imageinfo = cmds['imageinfo'](vol_config)
        action_result.set_status(phantom.APP_ERROR, VOL_ERR_UNABLE_TO_CHOOSE_A_PROFILE)

        try:
            for label, type, value in imageinfo.calculate():
                # self.debug_print('label', label)
                if (re.search('.*Suggested.*Profile.*', label)):
                    # self.debug_print('value', value)
                    m = re.search('(.*?),.*', value)
                    if m:
                        profile = m.group(1)
                        # self.debug_print('profile', profile)
                        return (action_result.set_status(phantom.APP_SUCCESS), profile)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, VOL_ERR_GET_PROFILE, e)

        return (action_result.get_status(), None)

    def _handle_psinfo(self, vault_id, vol_config, cmds, action_result):

        # First execute the dlllist plugin
        dlllist = cmds['dlllist'](vol_config)

        # the dlllist dictionary where the pid is the key
        dll_list = {}

        for obj in dlllist.calculate():
            pid = "{}".format(obj.UniqueProcessId)

            if (obj.Peb):
                curr_dict = {}
                curr_dict['command_line'] = "{}".format(str(obj.Peb.ProcessParameters.CommandLine or ''))
                dll_list[pid] = curr_dict
                modules = obj.get_load_modules()

                try:
                    path = next(modules)
                except StopIteration:
                    continue

                curr_dict['path'] = str(path.FullDllName)

        # Now run the psscan plugin
        psscan = cmds['psscan'](vol_config)

        num_of_processes = 0
        for obj in psscan.calculate():
            num_of_processes += 1
            pid = "{}".format(obj.UniqueProcessId)
            curr_dict = {
                "offset": "{}".format(hex(int(obj.obj_offset))),
                "name": "{}".format(obj.ImageFileName),
                "pid": "{}".format(obj.UniqueProcessId),
                "ppid": "{}".format(obj.InheritedFromUniqueProcessId),
                "pdb": "{}".format(hex(int(obj.Pcb.DirectoryTableBase))),
                "time_created": "{}".format(obj.CreateTime or ''),
                "time_exited": "{}".format(obj.ExitTime or ''),
                "command_line": "",
                "path": ""}

            # get info from dll list if present
            if (pid in dll_list):
                if ('command_line' in dll_list[pid]):
                    curr_dict['command_line'] = dll_list[pid]['command_line']
                if ('path' in dll_list[pid]):
                    curr_dict['path'] = dll_list[pid]['path']

            action_result.add_data(curr_dict)

        data_size = action_result.get_data_size()

        if (not data_size):
            # psscan did not complete successfully, try pslist
            self.debug_print("psscan did not yield any results, trying pslist")
            pslist = cmds['pslist'](vol_config)

            num_of_processes = 0
            for obj in pslist.calculate():
                num_of_processes += 1
                pid = "{}".format(obj.UniqueProcessId)
                curr_dict = {
                    "offset": "{}".format(hex(int(obj.obj_offset))),
                    "name": "{}".format(obj.ImageFileName),
                    "pid": "{}".format(obj.UniqueProcessId),
                    "ppid": "{}".format(obj.InheritedFromUniqueProcessId),
                    "pdb": "{}".format(hex(int(obj.Pcb.DirectoryTableBase))),
                    "time_created": "{}".format(obj.CreateTime or ''),
                    "time_exited": "{}".format(obj.ExitTime or ''),
                    "command_line": "",
                    "path": ""}

                # get info from dll list if present
                if (pid in dll_list):
                    if ('command_line' in dll_list[pid]):
                        curr_dict['command_line'] = dll_list[pid]['command_line']
                    if ('path' in dll_list[pid]):
                        curr_dict['path'] = dll_list[pid]['path']

                action_result.add_data(curr_dict)

        action_result.update_summary({VOL_JSON_NUM_PROCESSES: num_of_processes})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _move_file_to_vault(self, container_id, file_size, type_str, contains, local_file_path, action_result):

        self.save_progress(phantom.APP_PROG_ADDING_TO_VAULT)

        # lets move the data into the vault
        vault_details = action_result.add_data({})
        if (not file_size):
            file_size = os.path.getsize(local_file_path)

        vault_details[phantom.APP_JSON_SIZE] = file_size
        vault_details[phantom.APP_JSON_TYPE] = type_str
        vault_details[phantom.APP_JSON_CONTAINS] = contains
        vault_details[phantom.APP_JSON_ACTION_NAME] = self.get_action_name()
        vault_details[phantom.APP_JSON_APP_RUN_ID] = self.get_app_run_id()

        file_name = os.path.basename(local_file_path)

        vault_ret_dict = Vault.add_attachment(local_file_path, container_id, file_name, vault_details)

        if (vault_ret_dict.get('succeeded')):
            vault_details[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            vault_details[phantom.APP_JSON_NAME] = file_name
            action_result.set_status(phantom.APP_SUCCESS, VOL_SUCC_FILE_ADD_TO_VAULT,
                    vault_id=vault_ret_dict[phantom.APP_JSON_HASH])
        else:
            # print vault_ret_dict['message']
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message('. ' + vault_ret_dict['message'])

        return vault_details

    def _handle_process_extraction(self, vault_id, vault_file, profile, param):

        # Create and make the temp directory for this vault_file
        temp_dir = "/vault/tmp/{}".format(str(uuid.uuid4()))

        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        if not os.path.exists(temp_dir):
            return self.set_status(phantom.APP_ERROR, VOL_ERR_CANNOT_MAKE_TEMP_FOLDER)

        # Get the comma separated pid list
        pid_comma_separated = phantom.get_req_value(param, phantom.APP_JSON_PID)
        # Create an array of pid, get_list_from_string will remove blanks, empty elements and duplicates
        pid_list = phantom.get_list_from_string(pid_comma_separated)
        # Create the comma separated list again without the spaces, dumpfiles spits an error
        # if the pids are anything but comma separated
        pid_comma_separated = ','.join(pid_list)

        # The volatility command
        vol_command = "python2.7 {0} --filename={1} --profile={2} dumpfiles -n ".format(self._vol_py_path, vault_file, profile)
        vol_command += " --dump-dir {} -p {}".format(temp_dir, pid_comma_separated)

        # self.debug_print('vol_command', vol_command)

        # Execute it
        try:
            sout, serr, cmd_ret_code = phantom.run_ext_command(vol_command)
        except Exception as e:
            self.debug_print("Failed to execute '{0}'".format(vol_command), e)
            action_result = self.add_action_result(ActionResult(dict(param)))
            return action_result.set_status(phantom.APP_ERROR, "Failed to execute volatility command")

        # We ignore the return values of this command because it silently fails, the only
        # way to find out if the pid was extracted is to check for it's presence on disk
        # and fail if not found

        for pid in pid_list:

            # Create a action result to store this pid's status
            action_result = self.add_action_result(ActionResult(dict(param)))

            # Set the parameter
            action_result.update_param({phantom.APP_JSON_VAULT_ID: vault_id, phantom.APP_JSON_PID: pid})

            # Update the summary with the profile used
            action_result.update_summary({VOL_JSON_PROFILE_USED: profile})

            # Create a path to the image file
            image_filename = '{}/file.{}.*.exe.img'.format(temp_dir, pid)

            # Check if it exists
            files_matched = glob.glob(image_filename)

            # Only one should match since we are giving a pid
            if (len(files_matched) == 1):
                out_file_name = files_matched[0]
                self.debug_print('File Name', out_file_name)
                self._move_file_to_vault(self.get_container_id(), os.path.getsize(out_file_name),
                    VOL_CONST_EXTRACTED_PROCESS_FILE_TYPE, [VOL_CONST_EXTRACTED_PROCESS_FILE_TYPE, 'hash'],
                    out_file_name, action_result)
            else:
                action_result.set_status(phantom.APP_ERROR, VOL_ERR_EXTRACTED_PROCESS,
                        files_matched=len(files_matched),
                        should_match='1')

        # TODO: Write a util function to delete a non-empty directory.
        # os.rmdir or shutil.rmtree will not work
        # os.rmdir(temp_dir)
        return action_result.get_status()

    def _run_vol_cmd_shell(self, vol_plugin_cmd, vault_id, vault_file, profile, action_result, additional_switch=[]):

        temp_dir = "/vault/tmp/{}".format(str(uuid.uuid4()))

        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        if not os.path.exists(temp_dir):
            return action_result.set_status(phantom.APP_ERROR, VOL_ERR_CANNOT_MAKE_TEMP_FOLDER)

        out_file_name = "{0}/{1}.txt".format(temp_dir,
                vol_plugin_cmd.replace(' ', '_'))

        vol_command = []
        vol_command.append('python2.7')
        vol_command.append(self._vol_py_path)
        vol_command.append("--filename={}".format(vault_file))
        vol_command.append("--profile={}".format(profile))
        vol_command.append(vol_plugin_cmd)
        vol_command.extend(additional_switch)

        self.debug_print('vol_command', vol_command)

        try:
            sout, serr, cmd_ret_code = phantom.run_ext_command(vol_command)
        except Exception as e:
            self.debug_print("Failed to execute '{0}'".format(vol_command), e)
            return action_result.set_status(phantom.APP_ERROR, "Failed to execute volatility command")

        if (cmd_ret_code != 0):
            action_result.set_status(phantom.APP_ERROR, VOL_ERR_COMMAND, command=vol_plugin_cmd)
            action_result.append_to_message('. ' + serr.strip('\r\n '))
            return action_result.get_status()

        # write the stdout to the file
        with open(out_file_name, "w") as out_fp:
            out_fp.write(sout)

        # Add the name of the input vault_id file to the output file, it looks better, shows some relationship
        vault_file_info = Vault.get_file_info(container_id=self.get_container_id(), vault_id=vault_id)

        self.debug_print('vault_file_info: {0}'.format(vault_file_info))

        if (len(vault_file_info) > 0):
            generate_name = "{0}/{1}-{2}.txt".format(temp_dir,
                    vault_file_info[0][phantom.APP_JSON_NAME],
                    vol_plugin_cmd.replace(' ', '_'))
            shutil.move(out_file_name, generate_name)
            out_file_name = generate_name

        type_str = VOL_CONST_FORENSIC_FILE_TYPE.format(vol_plugin_cmd)
        self._move_file_to_vault(self.get_container_id(), os.path.getsize(out_file_name),
                type_str, [type_str], out_file_name, action_result)

        # TODO: Write a util function to delete a non-empty directory.
        # os.rmdir or shutil.rmtree will not work
        # os.rmdir(temp_dir)
        return action_result.get_status()

    def _run_mftparser_cmd(self, vault_id, vault_file, profile, action_result):

        return self._run_vol_cmd_shell('mftparser', vault_id, vault_file, profile, action_result)

    def _run_timeliner_cmd(self, vault_id, vault_file, profile, action_result):

        return self._run_vol_cmd_shell('timeliner', vault_id, vault_file, profile, action_result)

    def _run_cmdscan_cmd(self, vault_id, vault_file, profile, action_result):

        return self._run_vol_cmd_shell('cmdscan', vault_id, vault_file, profile, action_result)

    def _run_printkey_cmd(self, vault_id, vault_file, profile, action_result, param):

        additional_switch = []
        additional_switch.append('-K')
        additional_switch.append(str(param[VOL_JSON_KEY]))

        if (VOL_JSON_HIVE_ADDRESS in param):
            additional_switch.append('-o')
            additional_switch.append(str(param[VOL_JSON_HIVE_ADDRESS]))

        return self._run_vol_cmd_shell('printkey', vault_id, vault_file, profile, action_result, additional_switch)

    def _run_shellbags_cmd(self, vault_id, vault_file, profile, action_result):

        return self._run_vol_cmd_shell('shellbags', vault_id, vault_file, profile, action_result)

    def _run_iehistory_cmd(self, vol_config, cmds, action_result):

        iehistory = cmds['iehistory'](vol_config)

        for process, hist_record in iehistory.calculate():

            location = "{}".format(hist_record.Url)

            # strip all the data before http if present
            url_location = location.find("http")
            url = location[url_location:] if (url_location != -1) else location

            curr_data = {
                "offset": "{}".format(hex(int(hist_record.obj_offset))),
                "pid": "{}".format(process.UniqueProcessId),
                "image_filename": "{}".format(process.ImageFileName),
                "cache_type": "{}".format(hist_record.Signature),
                "record_length": "{}".format(hist_record.Length),
                "location": "{}".format(location),
                "url": "{}".format(url),
            }

            if (hist_record.obj_name == '_URL_RECORD'):
                curr_data['last_modified'] = "{}".format(hist_record.LastModified)
                curr_data['last_accessed'] = "{}".format(hist_record.LastAccessed)
                curr_data['file_offset'] = "{}".format(hist_record.FileOffset)
                curr_data['data_offset'] = "{}".format(hist_record.DataOffset)
                curr_data['data_length'] = "{}".format(hist_record.DataSize)

                if (hist_record.FileOffset > 0):
                    curr_data['file'] = "{}".format(hist_record.File)
                if (hist_record.has_data()):
                    curr_data['data'] = "{}".format(hist_record.Data)

            action_result.add_data(curr_data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_connections(self, vol_config, cmds, action_result):

        if (vol_config.PROFILE.find('WinXP') != -1):
            return self._run_connscan_cmd(vol_config, cmds, action_result)

        return self._run_netscan_cmd(vol_config, cmds, action_result)

    def _run_netscan_cmd(self, vol_config, cmds, action_result):

        netscan = cmds['netscan'](vol_config)

        addr_space = vol_utils.load_as(netscan._config, astype='physical')

        if (not netscan.is_valid_profile(addr_space.profile)):
            return action_result.set_status(phantom.APP_ERROR, VOL_ERR_NOT_SUPPORTED_FOR_PROFILE,
                    vol_command='netscan', profile=vol_config.PROFILE)

        for obj, proto, local_addr, local_port, remote_addr, remote_port, state in netscan.calculate():
            curr_data = {
                "offset": "{}".format(hex(int(obj.obj_offset))),
                'proto': "{}".format(proto),
                'local_ip': "{}".format(local_addr),
                'local_port': "{}".format(local_port),
                'remote_ip': "{}".format(remote_addr),
                'remote_port': "{}".format(remote_port),
                'state': "{}".format(state),
                'pid': "{}".format(obj.Owner.UniqueProcessId),
                'owner': "{}".format(obj.Owner.ImageFileName),
                'create_time': "{}".format(obj.CreateTime or '')
            }

            action_result.add_data(curr_data)

        action_result.update_summary({VOL_JSON_TOTAL_SOCKETS: action_result.get_data_size()})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_sockscan_cmd(self, vol_config, cmds, action_result):

        sockscan = cmds['sockscan'](vol_config)

        addr_space = vol_utils.load_as(sockscan._config, astype='physical')

        if (not sockscan.is_valid_profile(addr_space.profile)):
            return action_result.set_status(phantom.APP_ERROR, VOL_ERR_NOT_SUPPORTED_FOR_PROFILE,
                    vol_command='sockscan', profile=vol_config.PROFILE)

        for obj in sockscan.calculate():
            curr_data = {
                "offset": "{}".format(hex(int(obj.obj_offset))),
                'pid': "{}".format(obj.Pid),
                'local_port': "{}".format(obj.LocalPort),
                'proto': "{}".format(obj.Protocol),
                'protocol': "{}".format(protos.protos.get(obj.Protocol.v(), "-")),
                'local_ip': "{}".format(obj.LocalIpAddress),
                'create_time': "{}".format(obj.CreateTime)
            }

            action_result.add_data(curr_data)

        action_result.update_summary({VOL_JSON_TOTAL_SOCKETS: action_result.get_data_size()})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_connscan_cmd(self, vol_config, cmds, action_result):

        connscan = cmds['connscan'](vol_config)

        addr_space = vol_utils.load_as(connscan._config, astype='physical')

        if (not connscan.is_valid_profile(addr_space.profile)):
            return action_result.set_status(phantom.APP_ERROR, VOL_ERR_NOT_SUPPORTED_FOR_PROFILE,
                    vol_command='connscan', profile=vol_config.PROFILE)

        for obj in connscan.calculate():
            curr_data = {
                "offset": "{}".format(hex(int(obj.obj_offset))),
                'local_ip': "{}".format(obj.LocalIpAddress),
                'local_port': "{}".format(obj.LocalPort),
                'remote_ip': "{}".format(obj.RemoteIpAddress),
                'remote_port': "{}".format(obj.RemotePort),
                'pid': "{}".format(obj.Pid)
            }

            action_result.add_data(curr_data)

        action_result.update_summary({VOL_JSON_TOTAL_CONNECTIONS: action_result.get_data_size()})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_malfind_cmd(self, vol_config, cmds, action_result):

        mal = cmds['malfind'](vol_config)

        for task in mal.calculate():
            for vad, address_space in task.get_vads(vad_filter=task._injection_filter):
                if (mal._is_vad_empty(vad, address_space)):
                    continue

                content = address_space.zread(vad.Start, 64)

                curr_data = {
                    'process': "{}".format(task.ImageFileName),
                    'pid': "{}".format(task.UniqueProcessId),
                    'address': "{}".format(hex(int(vad.Start))),
                    'vad_tag': "{}".format(vad.Tag),
                    'protection': "{}".format(vadinfo.PROTECT_FLAGS.get(vad.u.VadFlags.Protection.v(), "")),
                    'flags': "{}".format(str(vad.u.VadFlags))
                }

                curr_data['buffer'] = "\r"
                for o, h, c in vol_utils.Hexdump(content):
                    curr_data['buffer'] += "{0:#010x} {1:<48} {2}".format(vad.Start + o, h, ''.join(c))
                    curr_data['buffer'] += "\r\n"

                curr_data['disassembly'] = "\r"
                for o, i, h in malfind.Disassemble(content, vad.Start):
                    curr_data['disassembly'] += "{0:#x} {1:<16} {2}".format(o, i, h)
                    curr_data['disassembly'] += "\r\n"

                action_result.add_data(curr_data)

        action_result.update_summary({VOL_JSON_POSSIBLE_MAL_INSTANCES_FOUND: action_result.get_data_size()})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_hivelist_cmd(self, vol_config, cmds, action_result):

        command = cmds['hivelist'](vol_config)

        # store the offsets here, need to keep track of them to ignore them properly in the loop below
        hive_offsets = []

        for hive in command.calculate():

            if hive.Hive.Signature != 0xbee0bee0:
                continue

            if hive.obj_offset in hive_offsets:
                continue

            try:
                name = str(hive.FileFullPath or '') or str(hive.FileUserName or '') or str(hive.HiveRootPath or '') or '[no name]'
            except AttributeError:
                name = '[no name]'

            curr_data = {
                'virtual': "{}".format(hex(int(hive.obj_offset))),
                'physical': "{}".format(hex(int(hive.obj_vm.vtop(hive.obj_offset)))),
                'name': "{}".format(name)}

            hive_offsets.append(hive.obj_offset)

            action_result.add_data(curr_data)

        action_result.update_summary({VOL_JSON_TOTAL_HIVES: action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_filescan_cmd(self, vol_config, cmds, action_result):

        command = cmds['filescan'](vol_config)

        for file in command.calculate():

            header = file.get_object_header()

            curr_data = {
                'offset': "{}".format(hex(int(file.obj_offset))),
                'ptr': "{}".format(header.PointerCount),
                'hnd': "{}".format(header.HandleCount),
                'access': str(file.access_string()),
                'name': str(file.file_name_with_device() or '')}

            action_result.add_data(curr_data)

        action_result.update_summary({VOL_JSON_TOTAL_FILES: action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_mutantscan_cmd(self, vol_config, cmds, action_result):

        command = cmds['mutantscan'](vol_config)

        for mutant in command.calculate():

            obj = mutant.get_object_header()

            if (mutant.OwnerThread > 0x80000000):
                thread = mutant.OwnerThread.dereference_as('_ETHREAD')
                cid = "{0}:{1}".format(thread.Cid.UniqueProcess, thread.Cid.UniqueThread)
                pid = "{0}".format(thread.Cid.UniqueProcess)
            else:
                cid = ""
                pid = ""

            curr_data = {
                'offset': "{}".format(mutant.obj_offset),
                'ptr': "{}".format(obj.PointerCount),
                'hnd': "{}".format(obj.HandleCount),
                'signal': "{}".format(mutant.Header.SignalState),
                'thread': "{}".format(mutant.OwnerThread),
                'cid': cid,
                'pid': pid,
                'name': str(obj.NameInfo.Name or '')}

            action_result.add_data(curr_data)

        action_result.update_summary({VOL_JSON_TOTAL_MUTEXES: action_result.get_data_size()})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_driverscan_cmd(self, vol_config, cmds, action_result):

        # driverscan command
        command = cmds['driverscan'](vol_config)

        # for obj, drv_obj, ext_obj in command.calculate():
        for drv_obj in command.calculate():

            ext_obj = drv_obj.DriverExtension
            obj = drv_obj.get_object_header()

            curr_data = {
                'offset': "{}".format(hex(int(drv_obj.obj_offset))),
                'pointer_count': "{}".format(obj.PointerCount),
                'handle_count': "{}".format(obj.HandleCount),
                'start': "{}".format(hex(int(drv_obj.DriverStart))),
                'size': "{}".format(drv_obj.DriverSize),
                'service_key': str(ext_obj.ServiceKeyName or ''),
                'name': str(obj.NameInfo.Name or ''),
                'driver_name': str(drv_obj.DriverName or '')}

            action_result.add_data(curr_data)

        action_result.update_summary({VOL_JSON_TOTAL_DRIVERS: action_result.get_data_size()})
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        # Get params
        vault_id = param[phantom.APP_JSON_VAULT_ID]

        # Create a action_result to hold the status for the profile creation
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            vault_file = Vault.get_file_path(vault_id)
        except Exception as e:
            status = action_result.set_status(phantom.APP_ERROR, "Error accessing vault file", e)
            return action_result.get_status()

        # Create the vol config, commands require it
        vol_config.LOCATION = "{}{}".format(VOL_CONST_FILE_URL_PROTO, vault_file)

        # self.debug_print('vol_config.LOCATION', vol_config.LOCATION)

        profile = param.get(VOL_JSON_PROFILE)

        if (not profile):

            self.save_progress("Trying to detect the volatility profile of the input file")
            status, profile = self._get_profile(vol_config, cmds, action_result)
            if (phantom.is_fail(status)):
                # failure, will need to return from here
                return action_result.get_status()

        # We have a profile, first set the status to failure, else it will show up as success if an exception occurs
        action_result.set_status(phantom.APP_ERROR)

        # Set it in the vol config
        vol_config.PROFILE = profile

        # Add this info to the summary
        action_result.update_summary({VOL_JSON_PROFILE_USED: profile})

        # Send the progress
        self.save_progress(VOL_PROG_USING_PROFILE, prof_name=profile)

        # Get the action
        action = self.get_action_identifier()

        status = phantom.APP_ERROR
        if (action == self.ACTION_ID_GET_PSINFO):
            try:
                status = self._handle_psinfo(vault_id, vol_config, cmds, action_result)
            except Exception as e:
                status = action_result.set_status(phantom.APP_ERROR, "", e)
        elif (action == self.ACTION_ID_EXTRACT_PROCESS):
            # Process extraction is a bit different, it supports multiple processes
            # and therefore possible to add more than one action results,
            # Therefore it's neccessary to remove the action_result that was just added
            # Also it runs volatility as a seperate process using popen, so it takes
            # the config as params
            self.remove_action_result(action_result)
            status = self._handle_process_extraction(vault_id, vault_file, profile, param)
        elif (action == self.ACTION_ID_RUN_DRIVERSCAN):
            status = self._run_driverscan_cmd(vol_config, cmds, action_result)
        elif (action == self.ACTION_ID_RUN_MUTANTSCAN):
            status = self._run_mutantscan_cmd(vol_config, cmds, action_result)
        elif (action == self.ACTION_ID_RUN_FILESCAN):
            status = self._run_filescan_cmd(vol_config, cmds, action_result)
        elif (action == self.ACTION_ID_RUN_HIVELIST):
            status = self._run_hivelist_cmd(vol_config, cmds, action_result)
        elif (action == self.ACTION_ID_RUN_MALFIND):
            status = self._run_malfind_cmd(vol_config, cmds, action_result)
        elif (action == self.ACTION_ID_RUN_SOCKSCAN):
            status = self._run_sockscan_cmd(vol_config, cmds, action_result)
        elif (action == self.ACTION_ID_LIST_CONNECTIONS):
            status = self._list_connections(vol_config, cmds, action_result)
        elif (action == self.ACTION_ID_RUN_IEHISTORY):
            status = self._run_iehistory_cmd(vol_config, cmds, action_result)
        elif (action == self.ACTION_ID_RUN_SHELLBAGS):
            status = self._run_shellbags_cmd(vault_id, vault_file, profile, action_result)
        elif (action == self.ACTION_ID_RUN_TIMELINER):
            status = self._run_timeliner_cmd(vault_id, vault_file, profile, action_result)
        elif (action == self.ACTION_ID_RUN_CMDSCAN):
            status = self._run_cmdscan_cmd(vault_id, vault_file, profile, action_result)
        elif (action == self.ACTION_ID_RUN_PRINTKEY):
            status = self._run_printkey_cmd(vault_id, vault_file, profile, action_result, param)
        elif (action == self.ACTION_ID_RUN_MFTPARSER):
            status = self._run_mftparser_cmd(vault_id, vault_file, profile, action_result)
        else:
            self.remove_action_result(action_result)
            return self.unknown_action()

        return status


if __name__ == '__main__':

    import sys
    import pudb
    import json

    pudb.set_trace()

    with open(argv_temp[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VolatilityConnector()
        connector.print_progress_message = True
        result = connector._handle_action(json.dumps(in_json), None)

        print result

    exit(0)
