from __future__ import print_function
from pylib.sqlite_createdb import sqlite_vt
import argparse
import random
import time

import pefile
import os.path
from capstone import *
from keystone import *



def parse_args():
    parser = argparse.ArgumentParser(description='rasta')
    parser.add_argument('input_file', type=str, help='The originals path to the executable file')

    args = parser.parse_args()
    return args


def main():
    
    ini_time = time.time() 

    args = parse_args()
    db=sqlite_vt()
    db.arregloERR(args.input_file)
    #db.printme2()
    db.close()

if __name__ == '__main__':
    main()
