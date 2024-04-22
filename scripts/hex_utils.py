import sys

def hexstr_to_u8_list(hex_str):
    hex_str = hex_str.lstrip('0x')
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    byte_array = bytes.fromhex(hex_str)
    return list(byte_array)

def u8_list_to_hexstr(u8_list):
    byte_array = bytes(u8_list)
    hex_str = byte_array.hex()
    return "0x" + hex_str

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hex_utils.py <hex_string> OR python hex_utils.py -l <u8_list>")
        sys.exit(1)
    
    if sys.argv[1] == "-l":
        # Convert from list of u8 integers to hex string
        try:
            # Assume the u8 list is passed in as comma-separated values
            u8_list = eval(sys.argv[2])
            # u8_list = [int(u8) for u8 in sys.argv[2].split(',')]
            print(u8_list_to_hexstr(u8_list))
        except ValueError:
            print("Invalid u8 list format. Ensure you are using comma-separated integers.")
            sys.exit(1)
    else:
        # Convert from hex string to list of u8 integers
        hex_string = sys.argv[1]
        print(hexstr_to_u8_list(hex_string))
