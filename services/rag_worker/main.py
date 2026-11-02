import logging
import time

from services.common.db import init_db
from services.rag_worker.worker import process_one


def run():
    logging.basicConfig(level=logging.INFO)
    init_db()
    while True:
        if not process_one():
            time.sleep(1.0)


if __name__ == "__main__":
    run()
