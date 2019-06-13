# File: soleraconnector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.import requests
import os
import json
import os.path
import requests


class SoleraConnector:
    def __init__(self, username, apiKey, ip, version=False):
        """ The initlization method for the SoleraConnector.

        Keyword arguments:
        username -- A string that is the username of the person making the requests
        apiKey -- A string of the apiKey
        ip -- A string of the IP address of the appliance
        """
        self.username = username
        self.apiKey = apiKey
        self.ip = ip

        if version is False:
            result = self.getVersion()
            if 'response' in result:
                version = result['response'].pop()
            elif 'resultCode' in result and result['resultCode'] == 'API_INVALID_USER_CODE':
                raise Exception('Invalid username/apiKey')
            else:
                raise Exception('Unable to determine api version')

        self.version = version

    def getVersion(self):
        baseUrl = "https://{}/api/list".format(self.ip)

        return self._request("GET", baseUrl)

    def callAPI(self, method, url, data={}, download=False):
        """ Calls the API of a service and returns the result.

        Keyword arguments:
        method -- A string of the HTTP Method(GET,POST)
        url -- A string of the api url(not complete url)
        data -- A Dictionary of the data that will be sent(default {})
        download -- A string of the name the file should be give.
            If no string is given it assumes it's not a download(default False)
        """
        if url[0:1] == '/':
            url = url[1:]
        baseUrl = "https://{}/api/v{}/{}".format(self.ip, self.version, url)

        return self._request(method, baseUrl, data, download)

    def _request(self, method, url, data={}, download=False):
        post = {}
        files = {}
        if len(data) != 0:
            for k, v in data.iteritems():
                if isinstance(v, basestring) and os.path.isfile(v):
                    files[k] = open(v, "rb")
                else:
                    post[k] = json.dumps(v)
            if method != "POST":
                post['_method'] = method
            f = requests.post(url, auth=(self.username, self.apiKey), data=post, files=files, verify=False)
        else:
            f = requests.get(url, auth=(self.username, self.apiKey), verify=False)

        # if got some internal server error when asset configuration is invalid and try to run get pcap action
        try:
            response = f.text
        except:
            raise Exception("Error while parsing the response")

        try:
            respDict = json.loads(response)

            if respDict.get('resultCode') and respDict.get('resultCode') != 'API_SUCCESS_CODE':
                return respDict
        except:
            pass

        # If download is true, download to correct area
        if download is not False:
            chunk_size = 1000
            with open(download, 'wb') as dfile:
                for chunk in f.iter_content(chunk_size):
                    dfile.write(chunk)
            filesize = os.path.getsize(download)
            return {'download_file': download, 'filesize': filesize}
        else:  # Else return the data
            return respDict
