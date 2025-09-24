# Inside Pandora's Box: dissecting the latest arsenal and tactics of APT27

Details are available at [VB conference website](https://www.virusbulletin.com/conference/vb2025/abstracts/inside-pandoras-box-dissecting-latest-arsenal-and-tactics-apt27/).

## Distribution Files

### decode_credui_dll.py

`credui.dll` implemented mechanism to XOR decode its code during runtime to obstruct both static and dynamic malware analysis.
This Python script will decode and patch the `credui.dll` file, so malware sample can be analyzed easier.

### solve_wmicodegen_apihashing.py

[File](./solve_wmicodegen_apihashing.py)

`wmicodegen.dll` (Type B Loader) used ROR13 API Hashing to obstruct static malware analysis.
This IDAPython script will create / apply a structure with mapping of actual API function name and hash value that the loader uses.

### unpack_and_decode_update_url.py (unpack_update_url.py)

[File](./unpack_and_decode_update_url.py)

`update.url` included the shellcode used to execute Pandora Loader.
This Python script will read the content of `update.url` file, and outputs the unpacked / decoded result.

## Author

[Naoki Takayama](https://x.com/mopisec)
