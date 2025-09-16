import lznt1 # reference: https://github.com/you0708/lznt1
import struct

with open('VmwareX64/update.url', 'rb') as shellcode_file:
	shellcode = bytearray(shellcode_file.read())

key = 0xC5606F8
for i in range(0x1E, len(shellcode), 4):
    dw = struct.unpack('<I', shellcode[i:i+4])[0]
    dw ^= key
    shellcode[i:i+4] = struct.pack('<I', dw)
    key = (key + dw) & 0xFFFFFFFF

shellcode = b'\x00' * 20 + shellcode
payload = lznt1.decompress(shellcode[0x9E3:0x9E3 + 0x106AA])

with open('VmwareX64/unpacked_update_url.bin', 'wb') as result_file:
    result_file.write(payload)
