#!/usr/bin/python3
"""
Based on: https://github.com/dnandha/firmware-patcher

This project tries to convert the same project from Xiaomi to Ninebot
"""

import keystone
import capstone
import struct

# https://web.eecs.umich.edu/~prabal/teaching/eecs373-f10/readings/ARMv7-M_ARM.pdf
MOVW_T3_IMM = [*[None]*5, 11, *[None]*6, 15, 14, 13, 12, None, 10, 9, 8, *[None]*4, 7, 6, 5, 4, 3, 2, 1, 0]
MOVS_T1_IMM = [*[None]*8, 7, 6, 5, 4, 3, 2, 1, 0]


def PatchImm(data, ofs, size, imm, signature):
    assert size % 2 == 0, 'size must be power of 2!'
    assert len(signature) == size * 8, 'signature must be exactly size * 8 long!'
    imm = int.from_bytes(imm, 'little')
    sfmt = '<' + 'H' * (size // 2)

    sigs = [signature[i:i + 16][::-1] for i in range(0, len(signature), 16)]
    orig = data[ofs:ofs+size]
    words = struct.unpack(sfmt, orig)

    patched = []
    for i, word in enumerate(words):
        for j in range(16):
            imm_bitofs = sigs[i][j]
            if imm_bitofs is None:
                continue

            imm_mask = 1 << imm_bitofs
            word_mask = 1 << j

            if imm & imm_mask:
                word |= word_mask
            else:
                word &= ~word_mask
        patched.append(word)

    packed = struct.pack(sfmt, *patched)
    data[ofs:ofs+size] = packed
    return (orig, packed)


class SignatureException(Exception):
    pass


def FindPattern(data, signature, mask=None, start=None, maxit=None):
    sig_len = len(signature)
    if start is None:
        start = 0
    stop = len(data) - len(signature)
    if maxit is not None:
        stop = start + maxit

    if mask:
        assert sig_len == len(mask), 'mask must be as long as the signature!'
        for i in range(sig_len):
            signature[i] &= mask[i]

    for i in range(start, stop):
        matches = 0

        while signature[matches] is None or signature[matches] == (data[i + matches] & (mask[matches] if mask else 0xFF)):
            matches += 1
            if matches == sig_len:
                return i

    raise SignatureException('Pattern not found!')


class FirmwarePatcher():
    def __init__(self, data):
        self.data = bytearray(data)
        self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

    """
    Info: Speed limit speed is the fastest speed mode
    
    --- FOUND AT (DRV173) SECTION ---
                             LAB_00006f24 
     
    
     
    
    00006f24 97 f8 51 b0     ldrb.w     r11,[r7,#0x51]=>DAT_200007cd
    00006f28 14 23           movs       r3,#0x14
    00006f2a 4f f4 fa 5a     mov.w      r10,#0x1f40
    00006f2e 4f f0 19 0c     mov.w      r12,#0x19
    
    ---> Offset: 0x6f2e
    """
    def speed_limit_speed_eu(self, km_h):
        signature = [0x97, 0xf8, 0x51, None, None, 0x23, 0x4f, 0xf4, 0xfa, 0x5a]
        register = 12
        add_offset = 0xa
        instruction_len = 4

        ofs = FindPattern(self.data, signature) + add_offset
        pre = self.data[ofs:ofs + instruction_len]
        assert pre[-1] == register
        post = bytes(self.ks.asm('MOV.W R{}, #{}'.format(register, km_h))[0])
        assert len(pre) == len(post)
        self.data[ofs:ofs + instruction_len] = post

        return "speed_limit_speed_eu", hex(ofs), pre.hex(), post.hex()

    """
    Almost same as eu (see above)
    ---> Offset: 0x6f28
    """

    def speed_limit_speed_de(self, km_h):
        signature = [0x97, 0xf8, 0x51, None, None, 0x23, 0x4f, 0xf4, 0xfa, 0x5a]
        add_offset = 0x4
        register = (0x23, 3)
        instruction_len = 2

        ofs = FindPattern(self.data, signature) + add_offset
        pre = self.data[ofs:ofs + instruction_len]
        assert pre[-1] == register[0]
        post = bytes(self.ks.asm('MOVS R{}, #{}'.format(register[1], km_h))[0])
        assert len(pre) == len(post)
        self.data[ofs:ofs + instruction_len] = post

        return "speed_limit_speed_de", hex(ofs), pre.hex(), post.hex()

    """
    --- FOUND AT (DRV173) SECTION ---
    000070fe 97 f8 52 20     ldrb.w     r2,[r7,#0x52]=>DAT_200007ce
    00007102 01 2a           cmp        r2,#0x1
    00007104 0c d0           beq        LAB_00007120
    00007106 28 22           movs       r2,#0x28
    
    ---> Offset: 0x7106
    """
    def speed_limit_speed_us(self, km_h):
        signature = [0x97, 0xf8, 0x52, None, 0x1, 0x2a, None, None, None, 0x22, 0xc2, 0x80]
        add_offset = 8
        register = (0x22, 2)
        instruction_len = 2

        ofs = FindPattern(self.data, signature) + add_offset
        pre = self.data[ofs:ofs + instruction_len]
        assert pre[-1] == register[0]
        post = bytes(self.ks.asm('MOVS R{}, #{}'.format(register[1], km_h))[0])
        self.data[ofs:ofs + instruction_len] = post

        return "speed_limit_speed_us", hex(ofs), pre.hex(), post.hex()


if __name__ == "__main__":
    import sys

    def eprint(*args, **kwargs):
        print(*args, file=sys.stderr, **kwargs)

    if len(sys.argv) != 4:
        eprint("Usage: {0} <orig-firmware.bin> <target.bin> [patches]".format(sys.argv[0]))
        eprint("Example: {0} DRV170.bin DRV170_patched.bin sls-de,sls-eu".format(sys.argv[0]))
        exit(1)

    infile, outfile, args = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(infile, 'rb') as fp:
        data = fp.read()

    patcher = FirmwarePatcher(data)

    patches = {
        'sls-eu': lambda: patcher.speed_limit_speed_eu(30),
        'sls-de': lambda: patcher.speed_limit_speed_de(30),
        'sls-us': lambda: patcher.speed_limit_speed_us(30)
    }

    for key in patches:
        if key not in args.split(',') and args != 'all':
            continue
        try:
            desc, ofs, pre, post = patches[key]()
            print(desc, ofs, pre, post)
            pre_dis = [' '.join([x.mnemonic, x.op_str])
                       for x in patcher.cs.disasm(bytes.fromhex(pre), 0)]
            post_dis = [' '.join([x.mnemonic, x.op_str])
                        for x in patcher.cs.disasm(bytes.fromhex(post), 0)]
            for pd in pre_dis:
                print("<", pd)
            for pd in post_dis:
                print(">", pd)
        except SignatureException:
            print('SignatureException', key)

    with open(outfile, 'wb') as fp:
        fp.write(patcher.data)
