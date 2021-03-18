"""Main script entrypoint for CHIRP."""

# Standard Python Libraries
from multiprocessing import freeze_support
import os

# cisagov Libraries
from chirp import run
from chirp.common import CONSOLE, ERROR, OUTPUT_DIR, save_log

if __name__ == "__main__":
    try:
        freeze_support()
        run.run()
        CONSOLE(
            "[green][+][/green] DONE! Your results can be found in {}.".format(
                os.path.abspath(OUTPUT_DIR)
            )
        )
    except KeyboardInterrupt:
        ERROR("Received an escape sequence. Goodbye.")
    finally:
        save_log()
        input()
