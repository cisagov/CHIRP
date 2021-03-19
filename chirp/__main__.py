"""Main method for CHIRP (Used when compiled)."""

# Standard Python Libraries
from multiprocessing import freeze_support
import os
import sys
import time

# cisagov Libraries
from chirp import run
from chirp.common import CONSOLE, ERROR, OUTPUT_DIR, save_log

if __name__ == "__main__":
    try:
        freeze_support()
        run.run()
        time.sleep(2)
        CONSOLE(
            "[green][+][/green] DONE! Your results can be found in {}. Press any key to exit.".format(
                os.path.abspath(OUTPUT_DIR)
            )
        )
        input()
        save_log()
        sys.exit(0)
    except KeyboardInterrupt:
        ERROR("Received an escape sequence. Goodbye.")
        save_log()
        sys.exit(0)
