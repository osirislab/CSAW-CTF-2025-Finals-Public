from phe import paillier
import pickle

with open('public.key', 'rb') as pubFile:
    public:paillier.PaillierPublicKey = pickle.load(pubFile)

    with open("logs/event.log", "w") as logs:
        logs.write(f"EVENT_LOG: jump.log reset\nNAVIGATOR_DEBUG: Jump Cache {public.encrypt(42).ciphertext()}\nSYSTEM_ERROR: Curcuit Overload; Emergency Shutdown\nSYSTEM_DEBUG: System Online\n")
        print("[INITIAL JUMP] Log done")
