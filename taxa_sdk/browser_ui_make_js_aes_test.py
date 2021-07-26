import binascii
from taxa_sdk import TaxaRequest

code = """@taxa.route("/test")
def test():
    response.add("decryption was successful")"""

req = TaxaRequest('browserUI.json')
req.ip = "52.138.6.109"

response = req.send(
    code=code,
    data={"a": 4},
    function="test"
)

#req.key_dump()
#print("app_id:", req.appId)

def to_b64(key):
    return binascii.b2a_base64(key)[:-1].decode()

test_code = """
<!DOCTYPE html>
<html>
  <head>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js" integrity="sha512-nOQuvD9nKirvxDdvQ9OMqe2dgapbPB7vYAMrzJihw5m+aNcf0dX53m6YxM4LgA9u8e9eg9QX+/+mPu8kCNpV2A==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  </head>

  <script>
    var encrypted = CryptoJS.AES.encrypt(
        "decryption was successful",
        CryptoJS.enc.Base64.parse("{{{master_key}}}"), // master key
        {
          iv: CryptoJS.enc.Base64.parse("{{{iv}}}"), // iv
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }
    ).toString();

    console.log("encrypted result:", encrypted);

    ///////////////////

    var decrypted = CryptoJS.AES.decrypt(
      "{{{encrypted}}}",  // encrypted message (made by pyaes)
      CryptoJS.enc.Base64.parse("{{{master_key}}}"),  // master key
      {
        iv: CryptoJS.enc.Base64.parse("{{{iv}}}"), // iv
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    ).toString(CryptoJS.enc.Utf8);

    console.log("decrypted result:", decrypted);
  </script>
</html>
"""

test_code = test_code.replace("{{{master_key}}}", to_b64(req.key_manager.master_key_key))
test_code = test_code.replace("{{{iv}}}", to_b64(req.key_manager.master_key_iv))
test_code = test_code.replace("{{{encrypted}}}", response['encrypted_data'][:-1])

print(test_code)
