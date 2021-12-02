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
