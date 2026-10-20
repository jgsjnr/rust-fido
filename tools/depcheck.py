import os

base = (r"C:\t\xtensa-esp32s3-espidf\release\build\esp-idf-sys-7047177beeb65407"
        r"\out")
# acha build.ninja raiz e procura a regra do aegis_usb.c.obj
for dp, dn, fn in os.walk(base):
    if "build.ninja" in fn:
        p = os.path.join(dp, "build.ninja")
        with open(p, errors="replace") as fh:
            for line in fh:
                if "aegis_usb.c" in line and ("COMPILE" in line or ".c.obj" in line or "$" in line[:4]):
                    print(line.strip()[:300])
        break
print("---flags---")
for dp, dn, fn in os.walk(base):
    if "flags.make" in fn and "aegis_usb" in dp:
        print(os.path.join(dp, "flags.make"))
        break
