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

payload = bytearray(lznt1.decompress(shellcode[0x9CF:0x11079]))
payload[0x3956:0x3968] = b'\x90' * (0x3968 - 0x3956)
compressed = lznt1.compress(payload)
shellcode[0x9CF:0x11079] = compressed + b'\x00' * (3 - (0x1E + len(compressed)) % 4)

key = 0xC5606F8
for i in range(0x1E, len(shellcode), 4):
    dw = struct.unpack('<I', shellcode[i:i+4])[0]
    dw ^= key
    shellcode[i:i+4] = struct.pack('<I', dw)
    key = (key + dw) & 0xFFFFFFFF

with open('VmwareX64/patched_update.url.bin', 'wb') as result_file:
    result_file.write(shellcode)
