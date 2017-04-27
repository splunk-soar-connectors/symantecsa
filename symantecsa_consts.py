# --
# File: symantecsa_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --


# Config variables
SYMANTECSA_CONFIG_USERNAME = "username"
SYMANTECSA_CONFIG_API_KEY = "api_key"
SYMANTECSA_CONFIG_DEVICE_IP = "device_ip"

# Action params for get packet details
SYMANTECSA_ACTION_PARAM_START_TIME = "start_time"
SYMANTECSA_ACTION_PARAM_END_TIME = "end_time"
SYMANTECSA_ACTION_PARAM_NAME = "name"
SYMANTECSA_ACTION_PARAM_FILTER = "filter"
SYMANTECSA_ACTION_PARAM_PORT = "port"
SYMANTECSA_ACTION_PARAM_PCAP_FORMAT = "pcap_format"
SYMANTECSA_ACTION_PARAM_PCAP_FORMAT_DEFAULT = "pcapng"

# Endpoints
SYMANTECSA_ENDPOINT_GET_PACKET_DETAILS = "/pcap/download/query"
SYMANTECSA_ENDPOINT_BASE_URI = "/api/v6/"
SYMANTECSA_ENDPOINT_TEST_CONNECTIVITY = "/api/v6/list"

SYMANTECSA_API_VERSION = "6"

# Action Result Messages
SYMANTECSA_GET_PCAP_SUCCESS = "PCAP file written to vault successfully"

# PCAP file download location
SYMANTECSA_PCAP_FILE_DOWNLOAD_LOCATION = "/vault/tmp/{NAME}.pcap"

API_SUCCESS_CODE = 200

# Test Connectivity Errors
SYMANTECSA_TEST_CONNECTIVITY_ERROR = "Error connecting to Symantec Security Analytics.  Please check your credentials and try again"
SYMANTECSA_TEST_CONNECTIVITY_PROGRESS = "Making a test REST call"
SYMANTECSA_TEST_CONNECTIVITY_START = "Querying Symantec Security Analytics using the base url {base_url}"
