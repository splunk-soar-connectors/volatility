# --
# File: volatility_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Json keys specific to volatility app's input parameters/config and the output result
VOL_JSON_NUM_PROCESSES = "number_of_processes"
VOL_JSON_PROFILE = "profile"
VOL_JSON_PROFILE_USED = "vol_profile_used"
VOL_JSON_TOTAL_CONNECTIONS = "total_connections"
VOL_JSON_TOTAL_DRIVERS = "total_drivers"
VOL_JSON_TOTAL_MUTEXES = "total_mutexes"
VOL_JSON_TOTAL_FILES = "total_files"
VOL_JSON_TOTAL_HIVES = "total_hives"
VOL_JSON_TOTAL_SOCKETS = "total_sockets"
VOL_JSON_POSSIBLE_MAL_INSTANCES_FOUND = "possibly_mal_instances"
VOL_JSON_KEY = "key"
VOL_JSON_HIVE_ADDRESS = "hive_address"

# Status messages for volatility app
VOL_ERR_UNABLE_TO_CHOOSE_A_PROFILE = "Unable to choose a profile automatically, please supply one"
VOL_ERR_GET_PROFILE = "Unable to detect the volatility profile. This could happen if the input file is not a proper image of a running system. Try to re-run the command by supplying a profile"  # noqa
VOL_ERR_EXTRACTED_PROCESS = "Process extraction failed. Search for extracted file found {files_matched} files, should find {should_match}."
VOL_ERR_COMMAND = "Volatility command '{command}' failed"
VOL_SUCC_COMMAND = "Volatility command succeeded"
VOL_ERR_CANNOT_MAKE_TEMP_FOLDER = "Cannot make temp directory"
VOL_SUCC_FILE_ADD_TO_VAULT = "File added to vault, with ID: {vault_id}"

# Progress messages format string
VOL_PROG_USING_PROFILE = "Using profile =  '{prof_name}'"
VOL_PROG_GENERATED_ID_FOR_EXTRACTION_TASK = "Generated id '{uuid}' for file extraction"
VOL_PROG_RUNNING_COMMAND = "Running volatility command '{plugin}'"

# Other constants used in the connector
VOL_CONST_FILE_URL_PROTO = "file://"
VOL_CONST_EXTRACTED_PROCESS_FILE_TYPE = "pe file"
VOL_CONST_FORENSIC_FILE_TYPE = "volatility {0} output"
VOL_ERR_NOT_SUPPORTED_FOR_PROFILE = "Volatility command '{vol_command}' not supported for profile '{profile}'"
