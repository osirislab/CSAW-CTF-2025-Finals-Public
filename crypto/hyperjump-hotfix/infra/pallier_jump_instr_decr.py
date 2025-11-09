from phe import paillier as pallier
import pickle
import sys

args = sys.argv[1:]

if len(args) < 1:
    print('Please provide data to decrypt!')
    sys.exit(1)

encrypted = int(args[0], 10)

with open('public.key', 'rb') as pk:
    public:pallier.PaillierPublicKey = pickle.load(pk)

    with open('private.key', 'rb') as sk:
        private:pallier.PaillierPrivateKey = pickle.load(sk)
    
        print(private.decrypt(pallier.EncryptedNumber(public, encrypted)))