import sys
import hashlib
import binascii
import numpy as np
from PIL import Image
from Crypto.Cipher import AES

# ================== FUNCTIONS ================== #

def load_image(name):
    return Image.open(name)

def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.Resampling.LANCZOS)
    return image

def generate_secret(size):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color1, color2, color3 = np.random.randint(255, size=3)
            new_secret_image.putpixel((x, y), (color1, color2, color3))
            new_secret_image.putpixel((x+1, y), (255-color1, 255-color2, 255-color3))
            new_secret_image.putpixel((x, y+1), (255-color1, 255-color2, 255-color3))
            new_secret_image.putpixel((x+1, y+1), (color1, color2, color3))
    return new_secret_image

def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    for x in range(0, width*2, 2):
        for y in range(0, height*2, 2):
            sec = secret_image.getpixel((x, y))
            msg = prepared_image.getpixel((x//2, y//2))
            color1 = (msg[0]+sec[0]) % 256
            color2 = (msg[1]+sec[1]) % 256
            color3 = (msg[2]+sec[2]) % 256
            ciphered_image.putpixel((x, y), (color1, color2, color3))
            ciphered_image.putpixel((x+1, y), (255-color1, 255-color2, 255-color3))
            ciphered_image.putpixel((x, y+1), (255-color1, 255-color2, 255-color3))
            ciphered_image.putpixel((x+1, y+1), (color1, color2, color3))
    return ciphered_image

def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size
    new_image = Image.new(mode="RGB", size=(width//2, height//2))
    for x in range(0, width, 2):
        for y in range(0, height, 2):
            sec = secret_image.getpixel((x, y))
            cip = ciphered_image.getpixel((x, y))
            color1 = (cip[0]-sec[0]) % 256
            color2 = (cip[1]-sec[1]) % 256
            color3 = (cip[2]-sec[2]) % 256
            new_image.putpixel((x//2, y//2), (color1, color2, color3))
    return new_image

def level_one_encrypt(imagename):
    message_image = load_image(imagename)
    size = message_image.size
    secret_image = generate_secret(size)
    secret_image.save("secret.jpeg")
    prepared_image = prepare_message_image(message_image, size)
    ciphered_image = generate_ciphered_image(secret_image, prepared_image)
    ciphered_image.save("2-share_encrypt.jpeg")

def construct_enc_image(ciphertext, relength, width, height):
    asciicipher = binascii.hexlify(ciphertext).decode()
    step = 3
    encimageone = [asciicipher[i:i+step] for i in range(0, len(asciicipher), step)]
    while len(encimageone) % 3 != 0:
        encimageone.append("101")
    encimagetwo = [
    (int(encimageone[i], 16) % 256,
     int(encimageone[i+1], 16) % 256,
     int(encimageone[i+2], 16) % 256)
    for i in range(0, len(encimageone), 3)
]
    encim = Image.new("RGB", (width, height))
    encim.putdata(encimagetwo[:relength])
    encim.save("visual_encrypt.jpeg")

def encrypt(imagename, password):
    im = Image.open(imagename)
    pix = im.load()
    width, height = im.size
    plaintext = ''.join([f"{pix[x,y][0]+100}{pix[x,y][1]+100}{pix[x,y][2]+100}" for y in range(height) for x in range(width)])
    relength = width * height
    plaintext += f"h{height}h" + f"w{width}w"
    while len(plaintext) % 16 != 0:
        plaintext += "n"
    obj = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    ciphertext = obj.encrypt(plaintext.encode())
    open(imagename + ".crypt", "wb").write(ciphertext)
    construct_enc_image(ciphertext, relength, width, height)
    print("Visual encryption done.")
    level_one_encrypt("visual_encrypt.jpeg")
    print("2-share encryption done.")

def decrypt(ciphername, password):
    secret_image = Image.open("secret.jpeg")
    ima = Image.open("2-share_encrypt.jpeg")
    new_image = generate_image_back(secret_image, ima)
    new_image.save("2-share_decrypt.jpeg")
    print("2-share decryption done.")
    ciphertext = open(ciphername, "rb").read()
    obj = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    decrypted = obj.decrypt(ciphertext).decode(errors='ignore').replace("n", "")
    newwidth = decrypted.split("w")[1]
    newheight = decrypted.split("h")[1]
    decrypted = decrypted.replace(f"h{newheight}h", "").replace(f"w{newwidth}w", "")
    step = 3
    finaltextone = [decrypted[i:i+step] for i in range(0, len(decrypted), step)]
    finaltexttwo = [(int(finaltextone[i])-100, int(finaltextone[i+1])-100, int(finaltextone[i+2])-100)
                    for i in range(0, len(finaltextone)-2, 3)]
    newim = Image.new("RGB", (int(newwidth), int(newheight)))
    newim.putdata(finaltexttwo)
    newim.save("visual_decrypt.jpeg")
    print("Visual decryption done.")

# ================== CLI ENTRY ================== #
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Cách dùng:")
        print("  python3 final_cli.py encrypt <image_file> <password>")
        print("  python3 final_cli.py decrypt <cipher_file> <password>")
        sys.exit(1)

    mode = sys.argv[1]
    filename = sys.argv[2]
    password_text = sys.argv[3]
    password = hashlib.sha256(password_text.encode()).digest()

    if mode == "encrypt":
        encrypt(filename, password)
    elif mode == "decrypt":
        decrypt(filename, password)
    else:
        print("Lệnh không hợp lệ. Dùng encrypt hoặc decrypt.")
