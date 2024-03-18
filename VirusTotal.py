import hashlib
import json
import logging
import mimetypes
import os
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import requests
from plyer import notification

VIRUS_TOTAL_API = None
REPORT = None
DESCRIPTION = None
RUN_DIRECTORY = os.getcwd()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_api_key():
    with open('keys.json', "r") as json_file:
        data = json.load(json_file)
        json_file.close()
        return data


def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    # copyFile(file_path)
    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except PermissionError:
        logging.error(f"Permission denied: {file_path}")
        return None


def get_index_of_file(file_path, files):
    for i in range(len(files)):
        if files[i][0] == file_path:
            return i
    return -1


def get_index_of_hash(hash, files):
    for i in range(len(files)):
        if files[i][1] == hash:
            return i
    return -1


def monitor_directory(directory):
    # Get the list of files in the directory
    folder_contents = os.listdir(directory)

    files = []
    # get base files
    for item in folder_contents:
        # Construct the full path of the file
        file_path = os.path.join(directory, item)
        # Check if it's a file
        if os.path.isfile(file_path):
            # If it's a file, add it to the list
            files.append([file_path, calculate_md5(file_path)])

    # Iterate over the files in the directory

    # Continuously monitor for new files
    while True:

        # Get the updated list of files in the directory
        folder_contents = os.listdir(directory)

        for item in folder_contents:

            file_path = os.path.join(directory, item)
            hash = calculate_md5(file_path)

            if os.path.isfile(file_path):
                # If the file is not already in the list, it's a new file
                if file_path not in [item for sublist in files for item in sublist]:  # check if file is in the 2d array
                    index = get_index_of_hash(hash, files)
                    if index != -1:
                        logging.info(f"File name has been modified: {file_path}")
                        files[index][0] = file_path

                    else:
                        # Add the new file to the list and calculate its hash
                        logging.info(f"New file detected: {file_path}")
                        files.append([file_path, hash])

                        thread = threading.Thread(target=submit_request, args=(file_path,))
                        thread.start()

                if hash not in [item for sublist in files for item in sublist]:
                    logging.info(f"File has been modified: {file_path}")
                    index = get_index_of_file(file_path, files)
                    if index != -1:
                        files[index][1] = hash
                        files.append([file_path, hash])

                        thread = threading.Thread(target=submit_request, args=(file_path,))
                        thread.start()

        time.sleep(1)  # Wait for 1 second


def generate_text_file(**kwargs):
    global RUN_DIRECTORY
    try:
        # Get the current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Define the filename with the timestamp
        filename = f"{timestamp}.txt"
        indexArray = kwargs['indexArray']
        array = kwargs['array']

        file_name = None
        last_analysis_stats = None
        description = None
        total_votes = None

        try:
            file_name_index = indexArray[indexArray.index('file_name') + 1]
            file_name = array[file_name_index][1]
        except ValueError as e:
            logging.error(f"Error occurred while getting file name: {e}")

        try:
            last_analysis_stat_index = indexArray[indexArray.index('last_analysis_stats') + 1]
            last_analysis_stats = array[last_analysis_stat_index][1]
        except ValueError as e:
            logging.error(f"Error occurred while getting last analysis stats: {e}")

        try:
            total_votes_index = indexArray[indexArray.index('total_votes') + 1]
            total_votes = array[total_votes_index][1]
        except ValueError as e:
            logging.error(f"Error occurred while getting total votes: {e}")

        try:
            description_index = indexArray[indexArray.index('ai_description') + 1]
            description = array[description_index][1]
        except ValueError as e:
            logging.error(f"Error occurred while getting description: {e}")

        # Write some content to the file
        with open(f"{RUN_DIRECTORY}/reports/{filename}", "w") as file:
            file.write(f"Timestamp: {timestamp}\n")

            if file_name:
                file.write(f"File: {file_name}\n\n")

            if last_analysis_stats:
                for key, value in last_analysis_stats.items():
                    file.write(f"{key}: {value}\n")
                file.write("\n")
                if total_votes:
                    file.write(f"Community Votes:\n")
                    file.write(f"harmless: {total_votes['harmless']}\n")
                    file.write(f"malicious: {total_votes['malicious']}\n\n\n")

                else:
                    file.write("No analysis stats available\n\n")

            else:
                file.write("No analysis stats available\n\n")

            if description:
                file.write(f"Description: {description[0]['analysis']}\n")
            else:
                file.write("No detailed description available\n")

            file.write("\n")
            file.write(kwargs['tip'])
            # file.write(description[0]['analysis'])

        return f"{RUN_DIRECTORY}/reports/{filename}"

    except Exception as e:
        print(f"Error generating text file: {e}")

    return "failed"


def send_notification(**kwargs):
    if kwargs['title'] == 'SAFE FILE':
        notification.notify(
            title=kwargs['title'],
            message=kwargs['desc'],
            app_icon=kwargs['icon'],  # You can specify an icon path here if needed
            timeout=5,  # Duration in seconds
        )
    else:
        notification.notify(
            title=kwargs['title'],
            message=kwargs['desc'],
            app_icon=kwargs['icon'],  # You can specify an icon path here if needed
            timeout=10,  # Duration in seconds
        )
        time.sleep(1)
        array = kwargs['array']
        createReport(array, kwargs['desc'])


def createReport(array, description):
    global DESCRIPTION, REPORT
    report_detail = []

    indexArray = []

    # keeps track of the indexes of the values
    for i in range(len(array)):
        if array[i][0] == 'total_votes':
            indexArray.append('total_votes')
            indexArray.append(i)
        elif array[i][0] == 'file_name':
            indexArray.append('file_name')
            indexArray.append(i)
        elif array[i][0] == 'last_analysis_stats':
            indexArray.append('last_analysis_stats')
            indexArray.append(i)
        elif array[i][0] == 'ai_description':
            indexArray.append('ai_description')
            indexArray.append(i)

    filePath = generate_text_file(
        indexArray=indexArray,
        array=array,
        tip=description
    )

    try:
        subprocess.Popen(['notepad.exe', filePath])  # Open the file with Notepad
    except Exception as e:
        print(f"Error opening file with Notepad: {e}")


def send_notification_thread(**kwargs):
    try:
        notificationThread = threading.Thread(target=send_notification, kwargs=kwargs)
        notificationThread.start()
        notificationThread.join()
    except Exception as e:
        logging.error(f"Error occurred while sending notification: {e}")


def getReport(link):
    global VIRUS_TOTAL_API_KEY
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUS_TOTAL_API_KEY
    }
    loop = True
    while loop:
        req = requests.get(link, headers=headers)
        data = req.json()
        status = data['data']['attributes']['status']
        if status == 'completed':
            logging.info('Report completed')  # Change print to logging
            loop = False
            link = data['data']['links']['item']
            req = requests.get(link, headers=headers)
            data = req.json()
            getResults(data)
        elif status == 'queued':
            logging.info("Report queued, waiting 15 seconds...")
            time.sleep(15)
        elif status == 'in-progress':
            logging.info("Report in progress, waiting 15 seconds...")
            time.sleep(15)
        else:
            logging.info("Report status unknown, waiting 30 seconds...")
            time.sleep(30)


def uploadFile(file_path):
    logging.info("Uploading file...")
    url = "https://www.virustotal.com/api/v3/files"
    file_name = os.path.basename(file_path)
    mime_type = mimetypes.guess_type(file_path)
    files = {
        "file": (file_name, open(file_path, "rb"), mime_type)
    }
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUS_TOTAL_API_KEY
    }

    response = requests.post(url, files=files, headers=headers)
    json_data = response.json()
    link = json_data.get('data', {}).get('links', {}).get('self')

    if link:
        thread = threading.Thread(target=getReport, args=(link,))
        thread.start()


def getResults(json_data):
    total_votes = None
    last_analysis_stats = None
    ai_description = None
    file_name = None

    results = []

    try:
        ai_description = json_data['data']['attributes']['crowdsourced_ai_results']
        results.append(['ai_description', ai_description])
    except Exception as e:
        logging.error(f"Error occurred while processing JSON data: {e}")

    try:
        total_votes = json_data['data']['attributes']['total_votes']
        results.append(['total_votes', total_votes])
    except Exception as e:
        logging.error(f"Error occurred while processing JSON data: {e}")

    try:
        file_name = json_data['data']['attributes']['meaningful_name']
        results.append(['file_name', file_name])
    except Exception as e:
        logging.error(f"Error occurred while processing JSON data: {e}")

    try:
        last_analysis_stats = json_data['data']['attributes']['last_analysis_stats']
        results.append(['last_analysis_stats', last_analysis_stats])
    except Exception as e:
        logging.error(f"Error occurred while processing JSON data: {e}")

    # Check if total_votes is not None and if malicious votes > 0

    # Check if last_analysis_stats is not None and handle malicious and suspicious stats
    if last_analysis_stats:
        if int(last_analysis_stats.get('malicious', 0)) > 0:
            try:
                send_notification_thread(
                    title='POSSIBLE VIRUS DETECTED',
                    desc=f'{file_name} is a possible virus that you have downloaded, proceed with upmost caution',
                    array=results,
                    icon='icons/critical.ico'
                )
            except Exception as e:
                logging.error(f"Error occurred while sending notification: {e}")

        if int(last_analysis_stats.get('suspicious', 0)) > 0:
            send_notification_thread(
                title='SUSPICIOUS FILE',
                desc=f'{file_name} is a suspicious file that you have downloaded, proceed with caution',
                array=results,
                icon='icons/warning.ico'
            )
        else:
            send_notification_thread(
                title='SAFE FILE',
                desc=f'{file_name} is a safe file that you have downloaded',
                array=results,
                icon='icons/safe.ico'
            )

def submit_request(file_path):
    logging.info("getting hash")
    global VIRUS_TOTAL_API_KEY, total_votes, REPORT, DESCRIPTION
    identifier = calculate_md5(file_path)

    url = f"https://www.virustotal.com/api/v3/files/{identifier}"

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUS_TOTAL_API_KEY
    }
    logging.info('Submitting request...')
    response = requests.get(url, headers=headers)
    json_data = response.json()
    error_code = json_data.get('error', {}).get('code')
    if error_code:
        logging.info(f"File not found on VirusTotal: {file_path}")
        uploadFile(file_path)
        return

    getResults(json_data)


def start():
    global VIRUS_TOTAL_API_KEY
    keys = get_api_key()

    if keys:
        virus_total = keys.get('virus_total')
        if virus_total:
            VIRUS_TOTAL_API_KEY = virus_total


if __name__ == "__main__":
    start()
    try:
        directory_to_monitor = str(Path.home() / "Downloads")
        monitor_directory(directory_to_monitor)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
