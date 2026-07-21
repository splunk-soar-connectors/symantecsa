# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")

from soleraconnector import SoleraConnector


class SoleraConnectorDownloadTests(unittest.TestCase):
    def test_failed_download_does_not_write_response_to_disk(self):
        response = Mock(ok=False, status_code=403, reason="Forbidden")
        response.headers = {}
        response.iter_content.side_effect = AssertionError("error response must not be streamed to disk")

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "capture.pcap"
            with patch("soleraconnector.requests.get", return_value=response, create=True):
                result = SoleraConnector("user", "api-key", "appliance", version="6")._request(
                    "GET", "https://appliance/pcap", download=str(destination)
                )

            self.assertEqual(result, {"resultCode": "HTTP_403", "errors": ["Forbidden"]})
            self.assertFalse(destination.exists())

    def test_oversized_download_is_removed(self):
        response = Mock(ok=True, status_code=200, reason="OK")
        response.headers = {}
        response.iter_content.return_value = [b"abc", b"def"]

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "capture.pcap"
            with patch("soleraconnector.MAX_PCAP_DOWNLOAD_SIZE", 5), patch("soleraconnector.requests.get", return_value=response, create=True):
                result = SoleraConnector("user", "api-key", "appliance", version="6")._request(
                    "GET", "https://appliance/pcap", download=str(destination)
                )

            self.assertEqual(result["resultCode"], "DOWNLOAD_SIZE_LIMIT_EXCEEDED")
            self.assertFalse(destination.exists())

    def test_streaming_exception_removes_partial_download(self):
        response = Mock(ok=True, status_code=200, reason="OK")
        response.headers = {}
        response.iter_content.side_effect = RuntimeError("connection dropped")

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "capture.pcap"
            with patch("soleraconnector.requests.get", return_value=response, create=True):
                with self.assertRaisesRegex(RuntimeError, "connection dropped"):
                    SoleraConnector("user", "api-key", "appliance", version="6")._request(
                        "GET", "https://appliance/pcap", download=str(destination)
                    )

            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
