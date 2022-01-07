[comment]: # "Auto-generated SOAR connector documentation"
# Volatility

Publisher: Phantom  
Connector Version: 1\.2\.31  
Product Vendor: Volatility Foundation  
Product Name: Volatility  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 2\.1\.478  

This app implements a variety of <b>investigative</b> actions on the <b>Volatility forensics analysis platform</b>\.

[comment]: # "File: readme.md"
[comment]: # "Copyright (c) 2014-2016 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Each of the actions take in an optional parameter called 'profile'. In the absence of this parameter
the app will try to find the profile to use by executing the 'imageinfo' command. The downside is
that actions will take longer time to execute since the memory dump file will require to be loaded
twice, once to get the profile and the next time to actually run the action.


### Supported Actions  
[list processes](#action-list-processes) - Queries the system memory dump file for a list of processes and their information  
[get process file](#action-get-process-file) - Extracts the process file from the memory dump  
[list drivers](#action-list-drivers) - Execute the driverscan volatility plugin to list loaded drivers  
[list mutexes](#action-list-mutexes) - Execute the mutantscan volatility plugin to list mutexes  
[list open files](#action-list-open-files) - Execute the filescan volatility plugin to list open files  
[find malware](#action-find-malware) - Execute the malfind volatility plugin to find injected code/dlls in user mode memory  
[list sockets](#action-list-sockets) - Execute the sockscan volatility plugin\. This command is only available on Windows XP and Windows 2003 Server\.  
[list connections](#action-list-connections) - Execute the netscan or connscan volatility plugin to list network connections  
[get browser history](#action-get-browser-history) - Execute the iehistory volatility plugin  
[list mrus](#action-list-mrus) - Execute the shellbags volatility plugin to get a list of MRUs \(Most recently used items\)  
[get timeline](#action-get-timeline) - Execute the timeliner volatility plugin  
[get command history](#action-get-command-history) - Execute the cmdscan volatility plugin  
[get registry key](#action-get-registry-key) - Execute the printkey volatility plugin  
[list mfts](#action-list-mfts) - Execute the mftparser volatility plugin to get a list of master file table entries  
[get registry hives](#action-get-registry-hives) - Execute the hivelist volatility plugin to get a list of registry hives  

## action: 'list processes'
Queries the system memory dump file for a list of processes and their information

Type: **investigate**  
Read only: **True**

The action first tries to run the psscan volatility plugin, but if this plugin does not yield any data, then the pslist plugin is executed

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.command\_line | string | 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.ppid | numeric |  `pid` 
action\_result\.data\.\*\.time\_created | string | 
action\_result\.data\.\*\.time\_exited | string | 
action\_result\.data\.\*\.path | string |  `file path` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.summary\.vol\_profile\_used | string |  `volatility profile` 
action\_result\.data\.\*\.offset | string | 
action\_result\.data\.\*\.pdb | string |   

## action: 'get process file'
Extracts the process file from the memory dump

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**pid** |  required  | PID of the process to extract | numeric |  `pid` 
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.parameter\.ph | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.pid | numeric |  `pid` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.data\.\*\.vault\_id | string |  `hash`  `pe file` 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.type | string |   

## action: 'list drivers'
Execute the driverscan volatility plugin to list loaded drivers

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.driver\_name | string | 
action\_result\.data\.\*\.service\_key | string | 
action\_result\.data\.\*\.offset | string | 
action\_result\.data\.\*\.pointer\_count | string | 
action\_result\.data\.\*\.start | string | 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.handle\_count | string |   

## action: 'list mutexes'
Execute the mutantscan volatility plugin to list mutexes

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.pid | string |  `pid` 
action\_result\.data\.\*\.hnd | string | 
action\_result\.data\.\*\.offset | string | 
action\_result\.data\.\*\.ptr | string | 
action\_result\.data\.\*\.signal | string | 
action\_result\.data\.\*\.thread | string | 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.summary\.vol\_profile\_used | string |  `volatility profile`   

## action: 'list open files'
Execute the filescan volatility plugin to list open files

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.message | string | 
action\_result\.data\.\*\.offset | string | 
action\_result\.data\.\*\.ptr | string | 
action\_result\.data\.\*\.hnd | string | 
action\_result\.data\.\*\.access | string | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.summary\.total\_files | numeric | 
action\_result\.summary\.vol\_profile\_used | string |  `volatility profile` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successmalwful | numeric |   

## action: 'find malware'
Execute the malfind volatility plugin to find injected code/dlls in user mode memory

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.process | string |  `file name` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.protection | string | 
action\_result\.data\.\*\.flags | string | 
action\_result\.data\.\*\.address | string | 
action\_result\.data\.\*\.vad\_tag | string | 
action\_result\.data\.\*\.buffer | string | 
action\_result\.data\.\*\.disassembly | string |   

## action: 'list sockets'
Execute the sockscan volatility plugin\. This command is only available on Windows XP and Windows 2003 Server\.

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data\.\*\.local\_ip | string |  `ip` 
action\_result\.data\.\*\.local\_port | numeric |  `port` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.protocol | string | 
action\_result\.data\.\*\.create\_time | string | 
action\_result\.data\.\*\.offset | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.summary\.vol\_profile\_used | string |  `volatility profile`   

## action: 'list connections'
Execute the netscan or connscan volatility plugin to list network connections

Type: **investigate**  
Read only: **True**

This action will execute the 'connscan' plugin for a WinXP profile or the 'netscan' plugin for Win7 and above\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data\.\*\.local\_ip | string |  `ip` 
action\_result\.data\.\*\.local\_port | numeric |  `port` 
action\_result\.data\.\*\.remote\_ip | string |  `ip` 
action\_result\.data\.\*\.remote\_port | string |  `port` 
action\_result\.data\.\*\.owner | string |  `file name` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.proto | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.create\_time | string | 
action\_result\.data\.\*\.offset | string |  `ip` 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.summary\.vol\_profile\_used | string |  `volatility profile` 
action\_result\.summary\.total\_connections | numeric |   

## action: 'get browser history'
Execute the iehistory volatility plugin

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.location | string | 
action\_result\.data\.\*\.cache\_type | string | 
action\_result\.data\.\*\.file\_offset | string | 
action\_result\.data\.\*\.image\_filename | string |  `file name` 
action\_result\.data\.\*\.offset | string | 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.data\_length | numeric | 
action\_result\.data\.\*\.last\_accessed | string | 
action\_result\.data\.\*\.last\_modified | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.summary\.vol\_profile\_used | string |  `volatility profile`   

## action: 'list mrus'
Execute the shellbags volatility plugin to get a list of MRUs \(Most recently used items\)

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.type | string |  `vault id`  `os memory dump`  `volatility shellbags output`   

## action: 'get timeline'
Execute the timeliner volatility plugin

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.type | string |  `os memory dump`  `vault id`  `volatility timeliner output`   

## action: 'get command history'
Execute the cmdscan volatility plugin

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.type | string |  `vault id`  `os memory dump`  `volatility cmdscan output`   

## action: 'get registry key'
Execute the printkey volatility plugin

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 
**key** |  required  | Registry key to extract the details of | string | 
**hive\_address** |  optional  | The virtual address of the hive to search in | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.type | string |  `vault id`  `os memory dump`  `volatility printkey output` 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.contains | string | 
action\_result\.data\.\*\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.app\_run\_id | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.vol\_profile\_used | string | 
action\_result\.parameter\.key | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.parameter\.hive\_address | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list mfts'
Execute the mftparser volatility plugin to get a list of master file table entries

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.type | string |  `vault id`  `os memory dump`  `volatility mftparser output`   

## action: 'get registry hives'
Execute the hivelist volatility plugin to get a list of registry hives

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Phantom Vault ID of the dump file | string |  `vault id`  `os memory dump` 
**profile** |  optional  | Volatility profile of the memory dump file | string |  `volatility profile` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.profile | string |  `volatility profile` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `os memory dump` 
action\_result\.message | string | 
action\_result\.data\.\*\.virtual | string | 
action\_result\.data\.\*\.physical | string | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.summary\.total\_hives | numeric | 
action\_result\.summary\.vol\_profile\_used | string |  `volatility profile` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 