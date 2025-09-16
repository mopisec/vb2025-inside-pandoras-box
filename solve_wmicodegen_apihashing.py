import idaapi
import idautils
import ida_funcs
import pefile

API_RESOLVER_FN = 0xFA0
DLL_LIST = [line.strip() for line in open('dll_list.txt', 'r').readlines()]
ENUM_NAME = 'APIHASH'

# Reference: https://gist.github.com/trietptm/5cd60ed6add5adad6a34098ce255949a
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


def calculate_hash(string):
    string = string.upper()
    
    hash_value = 0
    for char in string:
        tmp = ror(hash_value, 13, 32)
        hash_value = (char + tmp) & 0xFFFFFFFF
    
    return hash_value


def main():
    # Calculate hash value of API functions
    api_dict = {}
    dll_dict = {}
    for dll in DLL_LIST:
        try:
            pe = pefile.PE('C:\\Windows\\System32\\' + dll)
            api_list = [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
            api_list = [api for api in api_list if api != None]
        except (AttributeError, pefile.PEFormatError):
            continue
        
        dll_dict[calculate_hash(dll.encode())] = dll.upper().replace('.', '_')
        for api in api_list:
            api_dict[calculate_hash(api)] = api
    
    # Create enum type for API hash
    enum = idc.get_enum(ENUM_NAME)
    if enum == idc.BADADDR:
        enum = idc.add_enum(idaapi.BADNODE, ENUM_NAME, idaapi.hex_flag())
    
    # Collect used API hash values
    for xref in idautils.XrefsTo(API_RESOLVER_FN):
        ea = xref.frm
        while ea != idc.BADADDR:
            if idc.print_insn_mnem(ea) == 'mov' and idc.get_operand_type(ea, 0) == 1 and idc.get_operand_value(ea, 0) == 8:
                api_hash_value = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                break
            ea = idc.prev_head(ea)
        
        api_ea = ea
        
        ea = xref.frm
        while ea != idc.BADADDR:
            if idc.print_insn_mnem(ea) == 'mov' and idc.get_operand_type(ea, 0) == 1 and idc.get_operand_value(ea, 0) == 2:
                dll_hash_value = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                break
            ea = idc.prev_head(ea)
        
        dll_ea = ea
        
        # Print API hashing resolution result
        if api_hash_value not in api_dict:
            print(f'[-] Failed: {hex(api_hash_value)} used at {hex(api_ea)}')
        else:
            print(f'[+] Resolved: {hex(api_hash_value)} ---> {api_dict[api_hash_value].decode()} used at {hex(api_ea)}')
        
            # Add enum member and apply it
            enum_value = idc.get_enum_member(enum, api_hash_value, 0, 0)
            if enum_value == -1:
                idc.add_enum_member(enum, "API_" + api_dict[api_hash_value].decode(), api_hash_value)
            
            idc.op_enum(api_ea, 1, enum, 0)
        
        # Print API hashing resolution result
        if dll_hash_value not in dll_dict:
            print(f'[-] Failed: {hex(dll_hash_value)} used at {hex(dll_ea)}')
        else:
            print(f'[+] Resolved: {hex(dll_hash_value)} ---> {dll_dict[dll_hash_value].replace('_', '.')} used at {hex(dll_ea)}')
        
            # Add enum member and apply it
            enum_value = idc.get_enum_member(enum, dll_hash_value, 0, 0)
            if enum_value == -1:
                idc.add_enum_member(enum, "DLL_" + dll_dict[dll_hash_value], dll_hash_value)
            
            idc.op_enum(dll_ea, 1, enum, 0)


if __name__ == '__main__':
    main()
