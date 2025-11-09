from phe import paillier
import pickle

public, private = paillier.generate_paillier_keypair()

with open("public.key", "wb") as pub:
    pickle.dump(public, pub)

with open("private.key", "wb") as priv:
    pickle.dump(private, priv)