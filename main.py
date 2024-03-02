import os
import queue
import logging
import threading
from ClearCache import CacheClearer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
RUN_DIR = os.getcwd()


# Log some messages
# logging.debug('This is a debug message')
# logging.info('This is an info message')
# logging.warning('This is a warning message')
# logging.error('This is an error message')
# logging.critical('This is a critical message')

def clearCache(q):
    cache = CacheClearer()
    code = cache.clear_cache()
    q.put(code)


def virusTotal():
    os.chdir(RUN_DIR)
    os.system('python VirusTotal.py')


def main():
    q = queue.Queue()
    logging.info('clearing cache')
    clearCacheThread = threading.Thread(target=clearCache, args=(q,))
    clearCacheThread.start()
    clearCacheThread.join()

    logging.info('running virusTotal')
    virusTotalThread = threading.Thread(target=virusTotal)
    virusTotalThread.start()


if __name__ == '__main__':
    main()
