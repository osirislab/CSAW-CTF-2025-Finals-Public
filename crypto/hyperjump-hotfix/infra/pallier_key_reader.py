from phe import paillier as pallier
import pickle
import sys

args = sys.argv[1:]

if len(args) > 0:
    with open(args[0], 'rb') as key_dir:
        public:pallier.PaillierPublicKey = pickle.load(key_dir)

        print(f"g:{public.g}\nn:{public.n}\nn**2:{public.nsquare}\n")
else:
    print('Please provide a key directory to read!\n')