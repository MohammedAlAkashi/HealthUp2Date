import os
import sys
import json
import time
import hashlib
import logging
import requests
import mimetypes
import threading

VIRUS_TOTAL_API_KEY = None
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_api_key(path):
    os.chdir(path)
    with open(f'{path}/keys.json', "r") as file:
            data = json.load(file)
            file.close()
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


def get_report(link, file_path):
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
            logging.info('Scan completed')  # Change print to logging
            loop = False
            link = data['data']['links']['item']
            req = requests.get(link, headers=headers)
            data = req.json()
            get_results(data, file_path, id)
        elif status == 'queued':
            logging.info("Scan is queued, waiting...")
            time.sleep(15)
        elif status == 'in-progress':
            logging.info("Scanning in progress, waiting...")
            time.sleep(5)
        else:
            logging.info("Scanning status unknown, waiting 30 seconds...")
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
        thread = threading.Thread(target=get_report, args=(link, file_path,))
        thread.start()


def get_results(json_data, file_path, id):
    total_votes = None
    last_analysis_stats = None
    ai_description = None
    file_name = None

    results = []
    id = json_data['data']['id']

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
        file_name = os.path.basename(file_path)

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
                logging.warning(f"POSSIBLE VIRUS: {file_name} is a possible virus, proceed with upmost caution")
                logging.warning(f"Details: https://www.virustotal.com/gui/file/{id}")
            except Exception as e:
                logging.error(f"Error occurred while sending notification: {e}")

        if int(last_analysis_stats.get('suspicious', 0)) > 0:
            logging.warning(f"SUSPICIOUS FILE: {file_name} is a suspicious file, proceed with caution")
            logging.warning(f"Details: https://www.virustotal.com/gui/file/{id}")
        else:
            logging.info(f"File is clean: {file_name}")
            logging.info(f"Details: https://www.virustotal.com/gui/file/{id}")


def submit_request(file_path):
    logging.info("Getting hash...")
    global VIRUS_TOTAL_API_KEY, total_votes, REPORT, DESCRIPTION
    identifier = calculate_md5(file_path)
    logging.info(f"Hash: {identifier}")

    url = f"https://www.virustotal.com/api/v3/files/{identifier}"

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUS_TOTAL_API_KEY
    }
    logging.info('Submitting hash...')
    response = requests.get(url, headers=headers)
    json_data = response.json()
    error_code = json_data.get('error', {}).get('code')
    if error_code:
        logging.info(f"Hash not found on VirusTotal: {file_path}")
        uploadFile(file_path)
        return
    id = json_data['data']['links']['self']
    get_results(json_data, file_path, id)


def start(path):
    global VIRUS_TOTAL_API_KEY
    keys = get_api_key(path)

    if keys:
        virus_total = keys.get('virus_total')
        if virus_total:
            VIRUS_TOTAL_API_KEY = virus_total

    else:
        logging.error("API key not found")
        return


if __name__ == '__main__':
    runDir = os.getcwd()
    user_profile = os.environ.get('USERPROFILE')
    onedrive_path = os.path.join(user_profile, 'OneDrive')
    path = os.path.join(onedrive_path, 'Documents')
    try:
        with open(f"{path}/keys.json", "r") as file:
                data = json.load(file)
                if data.get('ran') == "true":
                    pass
                else:
                    logging.info("First run")
                    logging.info("Installing modules...")
                    logging.info("Installing requests...")
                    os.system("pip install requests")
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logging.error("File not found")
        logging.info("Creating file...")
        with open(f"{path}/keys.json", "w") as file:
            jsonFormat = {
                "ran": "true",
                "virus_total": ""
            }
            json.dump(jsonFormat, file, indent=4)
        logging.info("File created")
        logging.info("Installing modules...")
        logging.info("Installing requests...")
        os.system("pip install requests")
        pass

    if sys.argv[1] == "--vkey":
        jsonFormat = {
            "ran": "true",
            "virus_total": sys.argv[2]
        }

        os.chdir(path)
        with open(f"./keys.json", "w") as file:
            json.dump(jsonFormat, file, indent=4)

        logging.info("Key added")

    else:
        start(path)
        os.chdir(runDir)
        path = sys.argv[1]
        submit_request(path)

