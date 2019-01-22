#   Copyright 2019 Check Point Software Technologies LTD

import os
import sys
import traceback

from .cli import log, main

if __name__ == '__main__':
    try:
        main(sys.argv)
    except SystemExit as e:
        sys.exit(e.code)
    except:
        log('%s\n' % traceback.format_exc())
        sys.exit(1)
