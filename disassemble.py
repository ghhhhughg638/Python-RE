"""Read a PE executable and disassemble a bounded range without modifying it."""
import argparse
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe', type=Path, help='Path to a 64-bit PE executable')
    parser.add_argument('--rva', required=True, type=lambda x: int(x, 0), help='Relative virtual address, e.g. 0x4a841a0')
    parser.add_argument('--size', type=lambda x: int(x, 0), default=128, help='Bytes to read (default: 128; maximum: 65536)')
    args = parser.parse_args()
    if not 1 <= args.size <= 65536:
        parser.error('--size must be between 1 and 65536')
    pe = pefile.PE(str(args.exe), fast_load=True)
    if pe.FILE_HEADER.Machine != 0x8664:
        parser.error('only x86-64 PE files are supported')
    data = pe.get_data(args.rva, args.size)
    if not data:
        parser.error('RVA does not map to file data')
    base = pe.OPTIONAL_HEADER.ImageBase
    print(f'Image base: {base:#x}  RVA: {args.rva:#x}  File offset: {pe.get_offset_from_rva(args.rva):#x}')
    for ins in Cs(CS_ARCH_X86, CS_MODE_64).disasm(data, base + args.rva):
        print(f'{ins.address:#x}  {ins.mnemonic:8} {ins.op_str}')


if __name__ == '__main__':
    main()
