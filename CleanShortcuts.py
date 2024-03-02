import os
import sys
import pylnk3
import logging

logging.basicConfig(level=logging.INFO)


def find_valid_directory(file_path):
    """
    Recursively searches for a valid directory starting from the directory of the file pointed by file_path.
    """
    current_dir = os.path.dirname(file_path)

    # Check if the current directory is valid
    if os.path.exists(current_dir):
        return current_dir

    # If the current directory is not valid, move up one level
    parent_dir = os.path.dirname(current_dir)
    if parent_dir == current_dir:  # Reached the root directory
        return None

    # Recursively search in the parent directory
    return find_valid_directory(parent_dir)


def delete_empty_folders(start_path):
    """
    Recursively deletes empty folders starting from the given start_path.
    """
    if not os.path.exists(start_path):
        return

    # Check if the directory is empty
    if not os.listdir(start_path):
        # Delete the directory if it's empty
        os.rmdir(start_path)
        logging.info(f'Deleted empty directory: {start_path}')

        # Move up to the parent directory
        parent_dir = os.path.dirname(start_path)
        delete_empty_folders(parent_dir)  # Recursively check and delete empty parent directories


def main():
    # Get the path from command line argument
    if len(sys.argv) < 2:
        print("Usage: python script.py <path>")
        sys.exit(1)

    path = sys.argv[1]

    # Check if the path exists
    if not os.path.exists(path):
        logging.error(f"Path '{path}' does not exist.")
        sys.exit(1)

    # Look for shortcuts in the specified path
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.lnk'):
                shortcut_path = os.path.join(root, file)
                try:
                    with open(shortcut_path, 'rb') as file:
                        link = pylnk3.parse(file)
                        target_path = link.relative_path
                except Exception as e:
                    logging.error(f"Error parsing shortcut '{shortcut_path}': {e}")
                    continue

                # Check if the target path exists
                if not os.path.exists(target_path):
                    # Find a valid directory for target path
                    valid_dir = find_valid_directory(target_path)
                    if valid_dir:
                        # logging.info(f"Found valid directory for {target_path}: {valid_dir}")
                        # Delete empty folders starting from the valid directory
                        delete_empty_folders(valid_dir)
                    else:
                        logging.error(f"No valid directory found for {target_path}")


if __name__ == "__main__":
    main()
