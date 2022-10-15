#!/usr/bin/python3
import os
from xiaotea import *

if __name__ == '__main__':
    import sys

    def eprint(*args, **kwargs):
        print(*args, file=sys.stderr, **kwargs)

    if len(sys.argv) < 4 or sys.argv[3].lower() not in ['-enc', '-dec']:
        eprint("Usage: {0} <source.bin> <destination.bin> <-enc or -dec>".format(sys.argv[0]))
        eprint("Example: {0} DRV170.bin DRV170.bin.enc -enc".format(sys.argv[0]))
        exit(1)

    xt = XiaoTea()
    modes = {
        '-enc': (lambda d: xt.encrypt(d), 'encrypted'),
        '-dec': (lambda d: xt.decrypt(d), 'decrypted')
    }

    in_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2\
                   else in_path + '.out'
    if not os.path.isfile(in_path):
        print('File doesn\'t exist!')
        exit(0)
    if os.path.isfile(out_path):
        choice = input(f'\'{out_path}\' already exists override (y/n)? ')
        choice = choice.lower()
        if not (choice == 'y' or choice == 'yes'):
            exit(0)
    with open(in_path, 'rb') as infile:
        data = infile.read()
        infile.close()

    mode = modes[sys.argv[3].lower()]
    data = mode[0](data)
    with open(out_path, 'wb') as outfile:
        outfile.write(data)
        outfile.close()
    print(f'Successfully {mode[1]} to \'{out_path}\'')
