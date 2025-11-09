from PIL import Image, ImageDraw
import base64

s = base64.b64decode('Li0tLSAuLSAgLS0tIC0tLiAtLi4uIC0gLSAgLS4uICQuLSAgLi0tLSAtLS4tIC4gLi0uIC4tLSAtLS0uIC4gLi0uIC0uLS4uIC0uLS4gLS4uLiAuLS4tIC0tLSAuLS4uLi0tLSAuLS4tIC0tLiAuLS4tIC0tLi4uIC0uLS4gLS4uLS4tLiAtLi4uIC0uLS4gLi4uLS4=').decode()
u = 18
w = (u+2)*len(s)
i = Image.new("RGB", (w, 50), (255,255,255))
d = ImageDraw.Draw(i)
x = 5
for c in s:
    if c == '.':
        d.ellipse((x,20,x+u,20+u), fill=(0,0,0))
        x += u + 2
    elif c == '-':
        d.rectangle((x,23,x+u+6,23+u-6), fill=(0,0,0))
        x += u + 8
    elif c == ' ':
        x += u - 6

i.save("what_is_this.png")
print("what_is_this.png generated!")
