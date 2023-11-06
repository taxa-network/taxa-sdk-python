import hashlib, binascii

def get_userID(pk):
    pk_bytes = binascii.a2b_base64(pk)
    return "TXT" + hashlib.sha256(pk_bytes).hexdigest()[:32]
        
if __name__ == '__main__':
    import sys, json
    p = sys.argv[1]
    with open(p) as f:
        pk = json.loads(f.read())['client_cert']
    print(get_userID(pk))
