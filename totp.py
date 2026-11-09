import sys
import zxingcpp
from PIL import Image

if len(sys.argv) < 2:
    print("Usage: totp.py <picture_file>")
    sys.exit(1)

try:
    img = Image.open(sys.argv[1])
    results = zxingcpp.read_barcodes(img, formats=zxingcpp.BarcodeFormat.QRCode)
    otp = list(map(lambda i: i.text, filter(lambda x: x.text.startswith("otpauth://"), results)))

    if len(otp) == 0:
        print("No TOTP QR code found", file=sys.stderr)
        sys.exit(1)

    for i in otp:
        print(i)
except Exception as e:
    print(e)
