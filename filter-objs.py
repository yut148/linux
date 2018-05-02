#!/usr/bin/env python

import sys
import os

output = "filtered-objs"

def main():

    objs = []
    for arg in sys.argv:
        if os.path.exists(arg) and not arg in objs:
            objs.append(arg)

    with open(output, "w") as fp:
        for obj in objs:
            fp.write(obj + " ")

    return 0

if __name__ == "__main__":
    sys.exit(main())
