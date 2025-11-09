from PIL import Image
from PIL.PngImagePlugin import PngInfo
import numpy as np

# Step 1: Define flag and key
flag = 'csawctf{OSIRIS_violet_wins}'
key = 'JAYSTREETHACKERS'

def xor_bytes(flag, key):
    key_long = (key * ((len(flag) // len(key)) + 1))[:len(flag)]
    return bytes([ord(f) ^ ord(k) for f, k in zip(flag, key_long)])

xor_flag = xor_bytes(flag, key)

def is_violet(pixel):
    r, g, b = [int(x) for x in pixel]
    return (
        abs(r - 87) < 20 and
        abs(g - 6) < 20 and
        abs(b - 140) < 20
    )

def encode_flag_violet_only(image_file, flag_bytes, output_file):
    img = Image.open(image_file)
    arr = np.array(img)
    bin_flag = ''.join([format(b, '08b') for b in flag_bytes]) + '1111111111111110'
    flag_idx = 0
    
    for y in range(arr.shape[0]):
        for x in range(arr.shape[1]):
            pixel = arr[y, x][:3]
            if is_violet(pixel) and flag_idx < len(bin_flag):
                arr[y, x, 0] = (int(arr[y, x, 0]) & ~1) | int(bin_flag[flag_idx])
                flag_idx += 1
    
    out = Image.fromarray(arr)
    
    metadata = PngInfo()
    metadata.add_text("StopRightThere", "Do you even know our violet logo's pixels?")
    out.save(output_file, pnginfo=metadata)
    print(f"Flag bits encoded only in violet pixels ({flag_idx} bits). File: {output_file}")
    print("Metadata comment added successfully!")

encode_flag_violet_only('violet_torch.png', xor_flag, 'violet_torch_hard.png')
