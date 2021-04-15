"""Main script entrypoint for CHIRP."""

# Standard Python Libraries
import logging
from multiprocessing import freeze_support
import os
import sys
import time

# cisagov Libraries
from chirp import run
from chirp.common import (
    COMPLETE,
    NON_INTERACTIVE,
    OUTPUT_DIR,
    iocs_discovered,
    save_log,
    wait,
)

if __name__ == "__main__":
    try:
        freeze_support()
        run.run()
        time.sleep(2)
        logging.log(
            COMPLETE,
            "DONE! Your results can be found in {}".format(os.path.abspath(OUTPUT_DIR)),
        )
        iocs_discovered = iocs_discovered()
        save_log()
        # non-zero exit if iocs discovered and non_interactive mode enabled
        if NON_INTERACTIVE and iocs_discovered:
            sys.exit(1)
        else:
            wait()
            sys.exit(0)
    except KeyboardInterrupt:
        logging.error("Received an escape sequence. Goodbye.")
        save_log()
        # indicate abnormal exit with 2
        sys.exit(2)
