# credui.dll XOR decodes its code during runtime.
# Following code snippet will generate DLL file with decoded code in it.

with open('VmwareX64/credui.dll', 'rb') as dll_file:
	payload = bytearray(dll_file.read())

key = b'\x8D\x44'
for i in range(0x400, 0x400 + 0x8B0):
    payload[i] ^= key[i % len(key)]

with open('VmwareX64/credui_decrypted.bin', 'wb') as payload_file:
    payload_file.write(payload)
