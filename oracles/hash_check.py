import hashlib
import logging
import requests
from typing import Optional

logger = logging.getLogger(__name__)

def hash_check(cid: str, ipfs_gateway_url: str) -> str:
    """
    Oracle that verifies a file's content hash matches its claimed IPFS CID.

    Args:
    - cid (str): The IPFS CID to check.
    - ipfs_gateway_url (str): The URL of the IPFS gateway.

    Returns:
    - attestation (str): PASS if the hash matches, FAIL otherwise.
    """
    try:
        # Construct the IPFS URL
        ipfs_url = f"{ipfs_gateway_url}/ipfs/{cid}"

        # Fetch content from IPFS gateway
        response = requests.get(ipfs_url, timeout=10)

        # Check if the request was successful
        if response.status_code != 200:
            logger.error(f"Failed to fetch content from IPFS gateway. Status code: {response.status_code}")
            return "FAIL"

        # Compute SHA-256 of fetched content
        content_hash = hashlib.sha256(response.content).hexdigest()

        # Check if the computed hash matches the CID
        if content_hash == cid:
            logger.info("Hash matches CID. Attestation: PASS")
            return "PASS"
        else:
            logger.error(f"Hash mismatch. Computed hash: {content_hash}, CID: {cid}")
            return "FAIL"

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching content from IPFS gateway: {e}")
        return "FAIL"

def main():
    cid = "example_cid"
    ipfs_gateway_url = "https://ipfs.io"
    attestation = hash_check(cid, ipfs_gateway_url)
    print(attestation)

if __name__ == "__main__":
    main()
