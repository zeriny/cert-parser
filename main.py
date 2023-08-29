import argparse
import textwrap
from OpenSSL import crypto
from app.cert_helpers import parse_certinfo, parse_ct_entry

def parse_arguments():
    """Parses command line arguments. """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("Parse X.509 Certificates and CT Entry."))

    # if the argument is MUST required: set required=True
    parser.add_argument('-type', '--type', action='store', choices=['pem', 'der', 'entry'],
                        help='please choose a cert type to be parsed')
    parser.add_argument('-cert', '--certfile', type=str, action='store', help='the cert file to parse')
    parser.add_argument('-leaf', '--leafpath', type=str, action='store', help='the leaf file path')
    parser.add_argument('-extra', '--extrapath', type=str, action='store', help='the extra file path')

    args = parser.parse_args()

    return args



def main():
    args = parse_arguments()
    if args.type == "pem":
        if not args.certfile:
            print("Please select a certificate to parse (-cert <cert_file>)")
            return
        cert_file = args.certfile
        with open(cert_file, 'rb') as fd:
            cert = fd.read()
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        cert_info = parse_certinfo(cert_obj)
        print(cert_info)
    elif args.type == "der":
        if not args.certfile:
            print("Please select a certificate to parse (-cert <cert_file>)")
            return
        cert_file = args.certfile
        with open(cert_file, 'rb') as fd:
            cert = fd.read()
        cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        cert_info = parse_certinfo(cert_obj)
        print(cert_info)
    elif args.type == "entry":
        if not args.leaf:
            print("Please set the .leaf file (-leaf <xxx.leaf>)")
            return
        if not args.extra:
            print("Please set the .extra file (-leaf <xxx.extra>)")
            return
        leaf_file = args.leaf
        extra_file = args.extra
        cert_chain = parse_ct_entry(leaf_path=leaf_file, extra_path=extra_file)
        print("Got a chain of {} certs".format(len(cert_chain)))

    else:
        # showcase
        cert_file = "testdata/test.der"
        with open(cert_file, 'rb') as fd:
            cert = fd.read()
        cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        cert_info = parse_certinfo(cert_obj)
        print(cert_info)


if __name__ == '__main__':
    main()