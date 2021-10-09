#!/usr/bin/python
# -----------------------------------------------------------
# Python client that retrieves a feed from Maltiverse.com
# Stores results in a local CSV file ready to be consumed by Splunk ES
#
# (C) 2021 Maltiverse
# Released under GNU Public License (GPL)
# -----------------------------------------------------------
import os
import argparse
import json
import requests
import csv

parser = argparse.ArgumentParser()

parser.add_argument('--email', dest='maltiverse_email', required=True,
                    help='Specifies Maltiverse email for login. Required')
parser.add_argument('--password', dest='maltiverse_password', required=True,
                    help='Specifies Maltiverse password for login. Required')
parser.add_argument('--feed', dest='maltiverse_feed', required=True,
                    help='Specifies Maltiverse Feed ID to retrieve. Required')
parser.add_argument('--output-dir', dest='outputdir', default='./',
                    help='Specifies the CSV output directory.')
parser.add_argument('--verbose', dest='verbose', action="store_true", default=False,
                    help='Shows extra information during ingestion')
arguments = parser.parse_args()

# Script options
script_path = "."
login_obj = {
    'email': arguments.maltiverse_email,
    'password': arguments.maltiverse_password
    }

HEADERS = None

COUNT_IP = 0
COUNT_HOSTNAME = 0
COUNT_URL = 0
COUNT_SAMPLE = 0


# Authentication in Maltiverse service
try:
    data_login = requests.post('https://api.maltiverse.com/auth/login', json=login_obj)
    R_JSON = json.loads(data_login.text)
    if 'status' in R_JSON and R_JSON['status'] == 'success':
        if R_JSON['auth_token']:
            HEADERS = {'Authorization': 'Bearer ' + R_JSON['auth_token'] }
        else:
            print('Authentication failed')
            raise SystemExit()
    else:
        print('Authentication failed')
        raise SystemExit()

except requests.exceptions.RequestException as e: 
    raise SystemExit(e)

# Retrieving feed information
COLLECTION_URL = "https://api.maltiverse.com/collection/" + arguments.maltiverse_feed
COLL_RESP = requests.get(COLLECTION_URL, headers=HEADERS)
if COLL_RESP.status_code != 200:
    print('Feed does not exist')
    raise SystemExit()
else:
    COLL_OBJ = json.loads(COLL_RESP.text)

# Apply ranges if specified
FEED_URL = COLLECTION_URL + "/download"

# Download feed
print("")
print("Retrieving feed: " + COLL_OBJ['name'])
DATA = requests.get(FEED_URL, headers=HEADERS)

# Opening target files
file_maltiverse_ip = os.path.join(arguments.outputdir, "maltiverse-ip-" + COLL_OBJ['name'].lower().replace(' ','_') + ".csv")
file_maltiverse_hostname = os.path.join(arguments.outputdir, "maltiverse-hostname-" + COLL_OBJ['name'].lower().replace(' ','_') + ".csv")
file_maltiverse_url = os.path.join(arguments.outputdir, "maltiverse-url-" + COLL_OBJ['name'].lower().replace(' ','_') + ".csv")
file_maltiverse_sample = os.path.join(arguments.outputdir, "maltiverse-sample-" + COLL_OBJ['name'].lower().replace(' ','_') + ".csv")

# Iterate collection retrieve
with open(file_maltiverse_ip, 'w', newline='') as f_ip:
    with open(file_maltiverse_hostname, 'w', newline='') as f_hostname:
        with open(file_maltiverse_url, 'w', newline='') as f_url:
            with open(file_maltiverse_sample, 'w', newline='') as f_sample:

                ip_writer = csv.writer(f_ip, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                hostname_writer = csv.writer(f_hostname, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                url_writer = csv.writer(f_url, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                sample_writer = csv.writer(f_sample, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

                ip_writer.writerow(['description', 'ip', 'weight'])
                hostname_writer.writerow(['description', 'domain', 'weight'])
                url_writer.writerow(['description', 'http_referrer', 'http_user_agent', 'url', 'weight'])
                sample_writer.writerow(['description', 'file_hash', 'file_name', 'weight'])

                # Iterate elements in feed
                for element in json.loads(DATA.text):
                    # Generating description field
                    first_description = True
                    description_string = ""

                    for bl in element['blacklist'] or []:
                        
                        if first_description:
                            description_string = bl['description'] + " (" + bl['source'] + ")"
                            first_description = False
                        else:
                            description_string = description_string + ', ' + bl['description'] + " (" + bl['source'] + ")"
                    

                    if element['type'] == 'ip':
                        ip_writer.writerow([description_string, element['ip_addr'], ""])
                        COUNT_IP += 1
                    if element['type'] == 'hostname':
                        hostname_writer.writerow([description_string, element['hostname'], ""])
                        COUNT_HOSTNAME += 1
                    if element['type'] == 'url':
                        url_writer.writerow([description_string, "", "", element['url'], ""])
                        COUNT_URL += 1
                    if element['type'] == 'sample':
                        filename = None
                        if 'filename' in element:
                            filename = element['filename'][0]
                        sample_writer.writerow([description_string, element['sha256'], filename, ""])
                        COUNT_SAMPLE += 1

print("###########################################")
if not COUNT_IP:
    os.remove(file_maltiverse_ip)
    print("IPs Loaded\t\t: " + str(COUNT_IP)) 
else:
    print("IPs Loaded\t\t: " + str(COUNT_IP)+ "\t" + file_maltiverse_ip) 

if not COUNT_HOSTNAME:
    os.remove(file_maltiverse_hostname)
    print("Hostnames Loaded\t: " + str(COUNT_HOSTNAME))
else:
    print("Hostnames Loaded\t: " + str(COUNT_HOSTNAME)+ "\t" + file_maltiverse_hostname) 

if not COUNT_URL:
    os.remove(file_maltiverse_url)
    print("URLs Loaded\t\t: " + str(COUNT_URL))
else:
    print("URLs Loaded\t\t: " + str(COUNT_URL)+ "\t" + file_maltiverse_url) 

if not COUNT_SAMPLE:
    os.remove(file_maltiverse_sample)
    print("SHA256 Loaded\t\t: " + str(COUNT_SAMPLE))
else:
    print("URLs Loaded\t\t: " + str(COUNT_SAMPLE)+ "\t" + file_maltiverse_sample) 


print("PROCESSED\t\t: " + COLL_OBJ['name'])
print("###########################################")
print("")
