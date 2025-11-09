from PIL import Image
import numpy as np

def is_violet(pixel):
    r, g, b = [int(x) for x in pixel]
    return abs(r-87)<20 and abs(g-6)<20 and abs(b-140)<20

img = Image.open('violet_torch_hard.png')
arr = np.array(img)
bits = []
end_marker = "1111111111111110"
# Collect LSBs from red channel of violet pixels
for y in range(arr.shape[0]):
    for x in range(arr.shape[1]):
        pixel = arr[y, x][:3]
        if is_violet(pixel):
            bits.append(str(int(arr[y, x, 0]) & 1))
bitstream = ''.join(bits)
end_pos = bitstream.find(end_marker)
message_bits = bitstream[:end_pos]
# Form bytes from bits
bytes_list = [int(message_bits[i:i+8], 2) for i in range(0, len(message_bits), 8)]
hidden_data = bytes(bytes_list)
# XOR-decrypt with key
key = 'JAYSTREETHACKERS'
key_long = (key * ((len(hidden_data) // len(key)) + 1))[:len(hidden_data)]
flag = ''.join([chr(b ^ ord(k)) for b, k in zip(hidden_data, key_long)])
print(flag)  # --> csawctf{OSIRIS_violet_wins}
