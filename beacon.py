# Verify the NIST beacon
# Michiel Appelman <michiel@appelman.se>

import time
import OpenSSL
import hashlib
import requests
import argparse
import xml.etree.ElementTree as ET

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('timestamp', nargs='?', default="last", 
                      help=argparse.SUPPRESS)
    parser.add_argument("-c", "--cert", dest="cfile", metavar="CERT",
                      help="read certificate from CERT", default='./beacon.cer')
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                      help="be more verbose, otherwise only errors are printed")
    args = parser.parse_args()

    beacon = get(args.timestamp)

    if args.verbose:
        print "Timestamp: " + beacon['timeStamp']
        print "Output Value: " + beacon['outputValue']

    if verify(beacon['signatureValue'], beacon['data'], args.cfile) and args.verbose:
        print "Beacon signature verification passed."

    if check_output(beacon['signatureValue'], beacon['outputValue']) and args.verbose:
        print "Signature hash successfully matches Output Value."

def get(timestamp='last', base_url='https://beacon.nist.gov/rest/record/'):
    """Load a certain beacon record in a dict.

    timestamp -- integer or string "last" (default: "last")
    base_url  -- base URL for beacon record XML
                    (default: https://beacon.nist.gov/rest/record/)
    
    This also adds a 'data' field with the fields to be signed concatenated."""
    if timestamp != "last":
        try:
            int(timestamp)+1
        except ValueError:
            print "Provided timestamp must be integer or 'last'"
            return None
    try:
        record = requests.get(base_url + str(timestamp), verify=True)
    except:
        print "Error requesting " + base_url + str(timestamp)
        return None
    xml = ET.fromstring(record.content)
    beacon = {}
    for child in xml:
        beacon[child.tag] = child.text
    # Add the data to be signed to the dict as well.
    beacon['data'] = beacon['version'] + \
        "{0:08x}".format(int(beacon['frequency'])).decode("hex") + \
        "{0:016x}".format(int(beacon['timeStamp'])).decode("hex") + \
        beacon['seedValue'].decode("hex") + \
        beacon['previousOutputValue'].decode("hex") + \
        "{0:08x}".format(int(beacon['statusCode'])).decode("hex")
    return beacon

def reverse_sign(signature):
    """Converts a beacon signature from Little-Endian to Big-Endian.
    
    This is because the NIST Beacon Signature is generated using the Microsoft
    CryptoAPI."""
    return signature.decode("hex")[::-1]

def verify(signature, data, cfile='./beacon.cer'):
    """Check if the signature matches on the data.
    
    signature -- the reported signature value in the beacon
    data -- the constructed data to be checked to match the signature
    cfile -- the beacon public key certificate file (default: ./beacon.cer)"""
    try:
        cert_file = open(cfile, 'r').read()
    except IOError:
        print "Can not read certification file %s." % cfile
        return None
    beacon_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, \
    cert_file)
    try:
        OpenSSL.crypto.verify(beacon_cert, \
        reverse_sign(signature), data, 'sha512')
    except OpenSSL.crypto.Error:
        return False
    return True

def check_output(signature, output):
    """Test if the SHA512 hash of the signature matches the beacon output value.
    
    signature -- the signature value from the beacon
    output -- the output value from the beacon"""
    sign_hash = hashlib.sha512(signature.decode("hex")).hexdigest().upper()
    if sign_hash != output:
        return False
    return True

if __name__ == "__main__":
    main()
