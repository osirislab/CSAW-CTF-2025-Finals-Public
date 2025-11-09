# The Cat Ate My Homework

## Category
Forensics

## Difficulty
Easy

## Description
Fun fact: cats enjoy gnawing on paper! This innocent little creature ate my homework — can you recover it?

You’re given a JPEG file. Examine it in a hex editor and recover what’s hidden inside.

## Expected Knowledge
* File signatures and headers (especially JPEG structure)
* Carving embedded data using a hex editor
* Understanding of simple steganography techniques

## Time Spent
Roughly 30–45 minutes

## Tools
* Hex editor such as HxD or Bless
* Optionally binwalk or strings for quick scanning

## Artifacts
* `cat.jpg` – the corrupted homework file

## Flag
`csawctf{C@ts_Luv_3@7ing_p@per!}`
