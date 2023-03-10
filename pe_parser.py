import pefile
import hashlib
import os
import argparse
import lief
from datetime import datetime

def title_print(s) :
    print("\n"*2)
    print(f'{s:=^50}')



def check_is_pe(filename) :
    try :
        pe =  pefile.PE(filename)
    except Exception as e :
        print(f"File '{filename}' is not a PE file")
        exit()

    print(f"File '{filename}' is a PE file")
    return pe


def check_is_dll(pe):
    if pe.is_dll():
        print(f"File '{filename}' is a DLL")
    else:
        print(f"File '{filename}' is not a DLL")



def check_is_signed(filename) :

    try :
        pe = lief.PE.parse(filename)

        if pe.has_signatures:
            print("The file is signed.")
        else:
            print("The file is not signed.")

        return pe
    except Exception as e :
        print("The file is not signed.")


def check_has_richheader(pe_lief):
    try :
        rich_header = pe_lief.has_rich_header
        print("The file has a Rich header :")
        print("\n", pe_lief.rich_header)
    except Exception as e :
        print("The file does not have a Rich header")

def extract_timestamp(pe_lief):
    try:
        ts = pe_lief.header.time_date_stamps
        print("timestamp: {} ({})".format(ts, datetime.fromtimestamp(ts)))
    except Exception as e :
        print("The file doesn't have timestamp in header")


def check_debug_directorys(pe_lief):
    try:
        debug = pe_lief.debug
        if len(debug) > 0:
            for i in range(len(debug)):
                print("Has debug data:")
                print("\ttype: {}".format(debug[i].type.name))
                print("\ttimestamp: {} ({})".format(debug[i].timestamp, datetime.fromtimestamp(debug[i].timestamp)))
        else:
            print("The file does not have debug data")
    except:
        print("The file does not have debug data")



if __name__ == "__main__" :

    #Take filename from argument
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="The filename to check")
    args = parser.parse_args()
    filename = args.filename

    #Import PE file
    title_print("IMPORT PE FILE")
    pe = check_is_pe(filename)

    #Check if the pe file is DLL
    title_print("CHECK IF IS DDL")
    check_is_dll(pe)

    #Check if has signature
    title_print("CHECK IF IS SIGNED")
    pe_lief = check_is_signed(filename)

    #Check if has rich header
    title_print("CHECK IF RICH HEADERS")
    check_has_richheader(pe_lief)

    #Check if has rich header
    title_print("EXTRACT TIMESTAMP")
    extract_timestamp(pe_lief)

    #Check if this PE contains debug directory
    title_print("CHECK DEBUG DERECTORY")
    check_debug_directorys(pe_lief)
