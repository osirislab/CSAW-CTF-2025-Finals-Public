# Violet Torch (Forensics)

Welcome to the Violet Torch challenge!
> Files provided:  
> - `violet_torch_hard.png`  
> - `CanYouGuessWhatAmI.py`

---

## Challenge

**Description:**  
Somewhere inside this torch, Jay Street hackers have hidden their secret. Can you capture the flag by following the (violet) clues?

---

## Solution Steps

### 1. Recon

- Start with metadata:
    ```
    exiftool violet_torch_hard.png
    ```
    - You’ll find a hint:  
      `StopRightThere: Do you even know our violet logo's pixels?`

- This implies you should pay close attention to NYU’s signature violet color (RGB ~87, 6, 140).

---

### 2. The Mystery Script

- Run:
    ```
    python3 CanYouGuessWhatAmI.py
    ```
    - Produces: `what_is_this.png`

- Open the image: it’s a sequence of dots and dashes—Morse code—but there’s no mention of that in the code.  
- Use a Morse code translator (manual or online) to decode.

- The output is:  
    ```
    .--- .- -.-- ... - .-. . . - .... .- -.-. -.- . .-. ...
    ```
  This decodes to `JAYSTREETHACKERS` (the XOR key).

---

### 3. Extract The Data

- NYU Violet pixels (approx RGB(87,6,140) ±20 tolerance) in the image hold data in the LSB (least significant bit) of the **red** channel.
- Write a simple Python script using PIL/numpy to extract all the LSBs in order from those specific pixels.


---

### 4. Decrypt the Flag

- The bytes you extracted are XOR-encrypted.
- Use the key you decoded from Morse: `JAYSTREETHACKERS`
- Decrypt:


---

## Flag

- csawctf{OSIRIS_violet_wins}


---

## Notes

- Tools used: `exiftool`, `python`, Morse code translator
- Key skills: steganography, color analysis, bit-level extraction, XOR cipher, forensic intuition

---

*Good luck—and may the violet burns brightly for you!*
