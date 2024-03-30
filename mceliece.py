"""McEliece v0.1

Usage:
  mceliece.py [options] enc [FILE]
  mceliece.py [options] dec [FILE]
  mceliece.py [options] gen PUB_KEY_FILE PRIV_KEY_FILE
  mceliece.py (-h | --help)
  mceliece.py --version

Options:
  -b, --block        Interpret input/output as
                       block stream.
  -i, --poly-input   Interpret input as polynomial
                       represented by integer array.
  -o, --poly-output  Interpret output as polynomial
                       represented by integer array.
  -h, --help         Show this screen.
  --version          Show version.
  -d, --debug        Debug mode.
  -v, --verbose      Verbose mode.
"""
from docopt import docopt
import numpy as np
import sys
import logging

log = logging.getLogger("mceliece")

debug = False
verbose = False


def generate(pub_key_file, priv_key_file):
    # Since NTRU doesn't require key generation like McEliece, this function will remain empty
    pass


# NTRU Encryption function
def enc_ntru(data):
    data = data.encode('utf-8')
    pub_key = "myKey.pub.npz"

    input_arr = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    input_arr = np.trim_zeros(input_arr, 'b')
	# Encrypte the data
    encrypted_data = encrypt(pub_key, input_arr, True, True)
    print("Encrypted Message: ")
    print(encrypted_data)
	# Pack the data to send over the net
    packed_data = np.packbits(np.array(encrypted_data).astype(int)).tobytes()
    print("")
    print("Packed Data: ")
    print(packed_data)
    return packed_data

# NTRU Decryption function
def dec_ntru(data):
    priv_key = "myKey.priv.npz"
    input_arr = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    input_arr = np.trim_zeros(input_arr, 'b')
	# Decrypt received data
    decrypted_data = decrypt(priv_key, input_arr, True, True)
	# Get message from data
    decrypted_message = np.packbits(np.array(decrypted_data).astype(int)).tobytes()
    return decrypted_message


def encrypt(input_arr, block=False):
    # Use NTRU encryption
    return enc_ntru(input_arr)


def decrypt(input_arr, block=False):
    # Use NTRU decryption
    return dec_ntru(input_arr)


if __name__ == '__main__':
    args = docopt(__doc__, version='McEliece v0.1')
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    if args['--debug']:
        ch.setLevel(logging.DEBUG)
    elif args['--verbose']:
        ch.setLevel(logging.INFO)
    else:
        ch.setLevel(logging.WARN)
    root.addHandler(ch)

    log.debug(args)
    poly_input = bool(args['--poly-input'])
    poly_output = bool(args['--poly-output'])
    block = bool(args['--block'])
    input_arr, output = None, None
    if args['FILE'] is None or args['FILE'] == '-':
        input = sys.stdin.read() if poly_input else sys.stdin.buffer.read()
    else:
        with open(args['FILE'], 'rb') as file:
            input = file.read()
    log.info("---INPUT---")
    log.info(input)
    log.info("-----------")
    if poly_input:
        input_arr = np.array(eval(input))
    else:
        input_arr = np.unpackbits(np.frombuffer(input, dtype=np.uint8))
    input_arr = np.trim_zeros(input_arr, 'b')
    log.info("POLYNOMIAL DEGREE: {}".format(max(0, len(input_arr) - 1)))
    log.debug("BINARY: {}".format(input_arr))

    if args['gen']:
        generate(args['PUB_KEY_FILE'], args['PRIV_KEY_FILE'])
    elif args['enc']:
        output = encrypt(input_arr, block=block)
    elif args['dec']:
        output = decrypt(input_arr, block=block)

    if not args['gen']:
        if poly_output:
            print(list(output.astype(np.int)))
        else:
            sys.stdout.buffer.write(np.packbits(np.array(output).astype(np.int)).tobytes())
