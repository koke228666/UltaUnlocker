import collections, argparse, base64, json, zlib, re, requests, uuid, base64, random, string, time
def encode_config(config):
    """Encodes a JSON configuration into a vpn:// prefixed string."""
    # Use indent=4 to preserve indentation
    json_str = json.dumps(config, indent=4).encode() 

    # Compress data using zlib
    compressed_data = zlib.compress(json_str)

    # Add a 4-byte header with the original data length in big-endian format
    original_data_len = len(json_str)
    header = original_data_len.to_bytes(4, byteorder='big')
    
    # Combine header and compressed data, then encode with Base64
    encoded_data = base64.urlsafe_b64encode(header + compressed_data).decode().rstrip("=")
    return f"vpn://{encoded_data}"

def decode_config(encoded_string):
    """Decodes a vpn:// prefixed string into a JSON configuration."""
    encoded_data = encoded_string.replace("vpn://", "")
    padding = 4 - (len(encoded_data) % 4)
    encoded_data += "=" * padding
    compressed_data = base64.urlsafe_b64decode(encoded_data)

    # Try to decompress the data assuming it's zlib compressed
    try:
        # Read the original data length from the first 4 bytes of the header
        original_data_len = int.from_bytes(compressed_data[:4], byteorder='big')

        # Decompress the data starting from the 5th byte (after the header)
        decompressed_data = zlib.decompress(compressed_data[4:])

        if len(decompressed_data) != original_data_len:
            raise ValueError("Invalid length of decompressed data")

        # Use json.loads with object_pairs_hook=OrderedDict to preserve key order in the JSON
        return json.loads(decompressed_data, object_pairs_hook=collections.OrderedDict)
    except zlib.error:
        # If decompression fails, assume the data is just base64 encoded JSON
        return json.loads(compressed_data.decode(), object_pairs_hook=collections.OrderedDict)

def patch_IPs(deckey):
    keyjson = json.loads(json.dumps(deckey, indent=4))
    cfg_json = keyjson['containers'][0]['awg']['last_config']
    cfg_json = cfg_json.replace('allowed_ips', 'kkshkpoop')
    cfg_json = cfg_json.replace('AllowedIPs', 'kkshkpoop')
    keyjson['containers'][0]['awg']['last_config'] = cfg_json
    return keyjson

def get_mainkey(ultakey):
    decodedcfg = json.loads(json.dumps(decode_config(ultakey)))
    fakeuuid = str(uuid.uuid4())
    random_bytes = ''.join(random.choices(string.ascii_letters + string.digits, k=32)).encode('utf-8')
    fakekey = base64.b64encode(random_bytes).decode('utf-8')
    print(f'\nUsing {fakeuuid} as installation_uuid\n{fakekey} as public_key\n{decodedcfg["api_endpoint"]} as endpoint\n{decodedcfg["api_key"]} as api_key...\n')
    url = decodedcfg['api_endpoint']
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Api-Key {decodedcfg['api_key']}",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en,*",
        "User-Agent": "Mozilla/5.0"
    }
    data = {
        "app_version": "1.0.0.0",
        "installation_uuid": fakeuuid,
        "os_version": "windows",
        "public_key": fakekey
    }
    response = requests.post(url, headers=headers, json=data)
    key = response.json()['config']
    return key

if __name__ == '__main__':
    ultakey = input('Enter a key from @ulta_download_bot: ')
    ultafullkey = get_mainkey(ultakey)
    decryptedukey = decode_config(ultafullkey)
    print(encode_config(patch_IPs(decryptedukey)))
    time.sleep(5)
