#!/usr/bin/python3
import sys
import os
from xiaotea import *

if __name__ == '__main__':
    if len(sys.argv) == 1:
        exit(0)
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
    xt = XiaoTea()
    data = xt.decrypt(data)
    with open(out_path, 'wb') as outfile:
        outfile.write(data)
        outfile.close()
    print(f'Successfully decrypted to \'{out_path}\'')
