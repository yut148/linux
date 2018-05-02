#!/usr/bin/env python

import sys

output = "ar.output"

def main():
    objs = []
    for i, arg in enumerate(sys.argv):
        if ".o" in arg and not "built-in" in arg and i is not 2:
            objs.append(arg)

    with open(output, "aw") as fp:
        for obj in objs:
            fp.write(obj + " ")

    return 0

if __name__ == "__main__":
    sys.exit(main())
