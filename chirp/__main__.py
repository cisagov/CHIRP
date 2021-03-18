"""Main method for CHIRP (Used when compiled)."""

# Standard Python Libraries
from multiprocessing import freeze_support
import os

# cisagov Libraries
from chirp.common import CONSOLE, ERROR, OUTPUT_DIR, save_log
import chirp.run

if __name__ == "__main__":
    try:
        freeze_support()
        chirp.run.run()
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
