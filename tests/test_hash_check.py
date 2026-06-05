import unittest
import unittest.mock
import requests
from oracles.hash_check import hash_check

class TestHashCheck(unittest.TestCase):

    def test_valid_cid(self):
        # Mock a successful request with matching hash
        cid = "Qmexample"
        ipfs_gateway_url = "https://ipfs.io"
        with unittest.mock.patch('requests.get') as mock_get:
            mock_response = unittest.mock.Mock()
            mock_response.status_code = 200
            mock_response.content = b"example content"
            mock_get.return_value = mock_response
            import hashlib
            mock_response_hash = hashlib.sha256(b"example content").hexdigest()
            mock_get.return_value = mock_response
            attestation = hash_check(cid, ipfs_gateway_url)
            self.assertEqual(attestation, "PASS" if mock_response_hash == cid else "FAIL")

    def test_tampered_content(self):
        # Mock a successful request but with tampered content
        cid = "Qmexample"
        ipfs_gateway_url = "https://ipfs.io"
        with unittest.mock.patch('requests.get') as mock_get:
            mock_response = unittest.mock.Mock()
            mock_response.status_code = 200
            mock_response.content = b"tampered content"
            mock_get.return_value = mock_response
            attestation = hash_check(cid, ipfs_gateway_url)
            self.assertEqual(attestation, "FAIL")

    def test_gateway_timeout(self):
        # Mock a request that times out
        cid = "Qmexample"
        ipfs_gateway_url = "https://ipfs.io"
        with unittest.mock.patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout
            attestation = hash_check(cid, ipfs_gateway_url)
            self.assertEqual(attestation, "FAIL")

    def test_invalid_cid_format(self):
        # Test with an invalid CID format
        cid = "invalid_cid"
        ipfs_gateway_url = "https://ipfs.io"
        with unittest.mock.patch('requests.get') as mock_get:
            attestation = hash_check(cid, ipfs_gateway_url)
            self.assertEqual(attestation, "FAIL")

if __name__ == "__main__":
    unittest.main()
