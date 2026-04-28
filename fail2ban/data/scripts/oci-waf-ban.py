#!/usr/bin/env python3
import sys
import os
import base64
import tempfile
import oci

action = sys.argv[1]  # "ban" or "unban"
ip     = sys.argv[2]
cidr   = f"{ip}/32"

# Write the private key to a temp file (SDK needs a file path)
key_content = base64.b64decode(os.environ["OCI_KEY_CONTENT_BASE64"]).decode()
with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
    f.write(key_content)
    key_path = f.name

config = {
    "user":        os.environ["OCI_USER"],
    "fingerprint": os.environ["OCI_FINGERPRINT"],
    "tenancy":     os.environ["OCI_TENANCY"],
    "region":      os.environ["OCI_REGION"],
    "key_file":    key_path,
}

client = oci.waf.WafClient(config)
address_list_id = os.environ["OCID_WAF_BLOCKLIST"]

resp      = client.get_network_address_list(address_list_id)
addresses = list(resp.data.addresses)

if action == "ban":
    if cidr not in addresses:
        addresses.append(cidr)
elif action == "unban":
    addresses = [a for a in addresses if a != cidr]

client.update_network_address_list(
    address_list_id,
    oci.waf.models.UpdateNetworkAddressListAddressesDetails(
        addresses=addresses
    )
)

os.unlink(key_path)
print(f"{action} {cidr}: ok")