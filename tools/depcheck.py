import json
import subprocess

DB = (r"C:\t\xtensa-esp32s3-espidf\release\build\esp-idf-sys-7047177beeb65407"
      r"\out\build\compile_commands.json")
cc = json.load(open(DB))
for e in cc:
    if e["file"].replace("\\", "/").endswith("aegis_usb/aegis_usb.c"):
        cmd = e["command"]
        break
# troca o output para um .o de teste
import re
cmd = re.sub(r"-o \S+", "-o C:/t/ninja_test.o", cmd)
print("CMD:", cmd[:200], "...")
r = subprocess.run(cmd, shell=True, cwd=e["directory"],
                   capture_output=True, text=True)
print("RC=", r.returncode)
print((r.stdout + r.stderr)[-1500:])
