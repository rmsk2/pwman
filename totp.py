import qrtools
import sys


CMD_DECODE = "decode"
CMD_ENCODE = "encode"


def print_usage():
    print(f"usage:  totp {CMD_DECODE} <image_file_name> # writes data to stdout")
    print(f"        totp {CMD_ENCODE} <image_file_name> # reads data from stdin")


def main():
    if len(sys.argv) < 3:
        print_usage()
        return

    qr = qrtools.QR()

    if sys.argv[1] == CMD_DECODE:
        success = qr.decode(sys.argv[2])
        if not success:
            print("Unable to read QR code")
            return
        
        print(qr.data)
    elif sys.argv[1] == CMD_ENCODE:
        qr.data = sys.stdin.read()
        res = qr.encode(sys.argv[2])
        if res != 0:
            print("Unable to encode to QR code")
            return
    else:
        print_usage()

main()