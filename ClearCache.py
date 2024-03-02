import os
import shutil
import logging
import tempfile


class CacheClearer:
    def __init__(self):
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def clear_cache(self):
        logging.info('Starting cache clearing process...')
        tempdir = tempfile.gettempdir()
        logging.info(f'Temporary directory: {tempdir}')
        os.chdir(tempdir)
        contents = os.listdir(os.curdir)
        logging.info(f'Number of items in temporary directory: {len(contents)}')

        for data in contents:
            try:
                if os.path.isdir(f'./{data}'):
                    try:
                        os.rmdir(f'./{data}')  # Try to remove empty directory
                    except OSError:
                        shutil.rmtree(f'./{data}')  # Remove directory with contents
                elif os.path.isfile(f'./{data}'):
                    os.remove(f'./{data}')  # Delete file
                else:
                    logging.error(f'Neither file nor folder: {data}')
            except PermissionError:
                logging.error(f'Permission denied: {data}')
            except FileNotFoundError:
                logging.error(f"File '{data}' not found.")
        return 0
