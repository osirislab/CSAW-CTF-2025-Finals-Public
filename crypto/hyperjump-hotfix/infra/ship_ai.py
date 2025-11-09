import os
import sys
import time
import signal
import itertools
import hashlib as hl
import pickle
import random as rd
from phe import paillier as paillier

FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


print("Booting...")

with open("public.key", "rb") as pub:
    public: paillier.PaillierPublicKey = pickle.load(pub)

with open("private.key", "rb") as priv:
    private: paillier.PaillierPrivateKey = pickle.load(priv)

FLAG = "csawctf{Wh47_4b0u7_7h3_dr01d_4774ck_0n_7h3_w00k135}"

Scenarios = [
    (
        """You emerge in a thick, swirling nebula. Sensors immediately begin to malfunction, static filling every channel. The ship’s navigation systems display nonsense data. Plasma storms dance outside, rattling the hull.

Your ship is safe for now, but prolonged exposure will fry your electronics.""",
        False,
    ),
    (
        """Your ship jerks out of hyperspace into a field of derelict hulks. Before you can scan them, red signals blink on your radar — pirate raiders. They begin powering weapons, their comms mocking your 'easy catch.'

You are outgunned. Shields will hold for a while, but not long.""",
        False,
    ),
    (
        """You arrive too close to a collapsed star remnant. The ship shakes violently as its artificial gravity alarms scream. The engines groan, struggling against the massive pull. The hyperdrive is still functional — barely.

Stay here too long and you’ll be shredded by tidal forces.""",
        False,
    ),
    (
        """The jump drops you above a barren, ice-locked planet. No signals. No stations. Just endless frozen oceans and storming blizzards below. A minor coolant leak has sprung in the jump core from the strain.

The ship isn’t in danger yet, but you can feel the cold creeping into the systems.""",
        False,
    ),
    (
        """Space blooms green and purple outside your viewport. You’ve landed in the debris zone of an ancient war — shattered ships and broken satellites orbit a radioactive star. Sensors pick up high levels of ionizing radiation.

Your hull plating protects you for now, but every minute here is a gamble.""",
        False,
    ),
]


def reveal(x: int):
    byte_len = x.to_bytes((x.bit_length() + 7) // 8, "big")
    return hl.sha256(byte_len).hexdigest()


def encrypt(x):
    """
    homomorphic encryption goes here
    """
    return public.encrypt(x)


def badJump():
    scenario, deathState = rd.choice(Scenarios)
    print(f"{scenario}\n\n")
    return deathState


def hide_cursor():
    sys.stdout.write("\x1b[?251")
    sys.stdout.flush()


def show_cursor():
    sys.stdout.write("\x1b[?25h")
    sys.stdout.flush()


def spinner(text="Jumping", delay=0.08, seconds=2):
    hide_cursor()
    start = time.time()

    try:
        for ch in itertools.cycle(FRAMES):
            if seconds is not None and (time.time() - start) >= seconds:
                break

            sys.stdout.write(f"\r{text} {ch}")
            sys.stdout.flush()
            time.sleep(delay)
    finally:
        sys.stdout.write("\r" + " " * (len(text) + 2) + "\r")
        sys.stdout.flush()
        show_cursor()


def jumpInit():
    print("\n")
    spinner()


def talk():
    print(f"Initializing return to home-base...")
    print(f"ERROR! Hyperjump translator failure!")

    while True:
        print("\nRequest manual override? (Y/n):", end=" ")
        action = input()

        if action in ("n", "N"):
            """
            Let's wait a bit
            """
            print("\n\nWhelp guess we're stranded here :/")
            print("Powering off...")
            sys.exit(1)

        elif action in ("y", "Y"):
            """
            Try jumping manually
            """
            print("\nManual override initiated")
            jumpcoord = int(
                input("Please enter the hyperjump encrypted destination coordinate:")
            )

            print("Jump initiated")

            jumpInit()

            if checkJump(
                jumpcoord,
                "2ba630e1d9545e4b6196b9d5ee2d7d7ed9cdc6b1e1bf3b44e7646ae0ff6ec0eb",
            ):
                """
                Jump successful
                """
                print("You reached back to base safe and well!")
                print(f"You plant a flag to mark a successful voyage: {FLAG}")
                sys.exit(0)

            """
            Jump unsuccessful, bad event
            """
            if badJump():  # If death, exit
                os.kill(1, signal.SIGKILL)
                sys.exit(0)


def checkJump(jump, truth) -> True:
    """
    decrypts test to match with truth
    """
    try:
        folly = paillier.EncryptedNumber(public, jump)
        fool = private.decrypt(folly)

        return reveal(fool) == truth
    except TypeError:
        print("Jump code unrecognzied! Terminating conversation...")
        sys.exit(1)


if __name__ == "__main__":
    try:
        talk()
    except KeyboardInterrupt:
        print("\nShip control interrupted. Terminating conversation...")
        sys.exit(0)
    except OverflowError:
        print("\nUnauthorized jump coordinates requested! Terminating conversation...")
        sys.exit(0)
    except Exception as e:
        print("\nAI malfunction! Terminating conversation...")
        print(e)
        sys.exit(1)
