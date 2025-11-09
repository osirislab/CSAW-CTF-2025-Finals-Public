ciphertextHex:str = input('Ciphertext:')
ciphertext = int(ciphertextHex, 10)

nHex:str = input('public n:')
n = int(nHex, 10)
nsq = n * n

print(f'n**2:{nsq}')

multConvert = 2100 // 42

jump = (ciphertext ** multConvert) % nsq

print(jump)
