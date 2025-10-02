from PIL import Image
import os

os.makedirs("samples", exist_ok=True)

img = Image.new("RGB", (100, 100), color="white")
img.save("samples/test.png")

print("[+] Sample PNG created: samples/test.png")
