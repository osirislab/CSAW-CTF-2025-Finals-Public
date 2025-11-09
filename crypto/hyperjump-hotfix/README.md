# Hyperjump Hotfix 🚀

This challenge is a simple demonstration of homomorphic encryption, requiring an inversion of said operation to "inspire" the right encryption.

You are the pilot of a scouting spaceship. You have encountered a system failure in your hyperjump encryptor. Based off of your current location and your last
hyperjump coordinate encryption stored in your system log, you must manually send the encrypted coordinate of the destination of your home base.
## Instructions

### 1. Build the Docker Image

Run the following commands to build and run the Docker image:

```bash
          docker build -t hyperjump-hotfix-starjump .
          docker compose up
```
## Solution

Looking around the filesystem, one can discern as much
```haskell
          plaintext1: [p1]:= 42 (found in ./navcomp & suggested in docs/COMPLIANCE.md)
          ciphertext1: [E(p1)] (found in logs/event.log as initial jump) 
          plaintext2: [p2]:= 2100 (found in docs/COMPLIANCE.md)
          public key component n: [n] (found when running ./pallier_key_reader public.key)
```

According to Pallier Homomorphic properties

$$E(p_1)^\frac{p_2}{p_1} \bmod n^2 \to\ E(p_1 \cdot \frac{p_2}{p_1}) \to E(p_1)$$
Therefore $$E(42)^{50} \bmod (n^2) \to\ E(42 \cdot 50) \to E(2100)$$

Don't wanna do the math? Let the script do it for ya!:
```bash

python3 solve.py
```
Prompts you to enter **ciphertext** _(E(p1))_ & **n**

## Flag
csawctf{Wh47_4b0u7_7h3_dr01d_4774ck_0n_7h3_w00k135}
