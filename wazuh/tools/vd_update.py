#!/var/ossec/framework/python/bin/python3

from cgitb import text
from fileinput import close
from genericpath import exists
from tabnanny import check
from pathlib import Path
from tokenize import Token
import requests, urllib3, sys, json, logging, os, argparse, time
from socket import socket, AF_UNIX, SOCK_DGRAM

HEADERS={}
VERIFY=False
DEBUG=False
LOAD_DATA=False
CSV_EXPORT=False
LOGTEST=False
CSV_FILE='None'
CSV_CHAR = '|'
ACTION='WATCH_ALERTS'
sleepSec=0.3
# Socket definition
socketAddr = '/var/ossec/queue/sockets/queue'
# Disable warnings
requests.packages.urllib3.disable_warnings()


# Send a message to socket.
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:vulnerability-detector:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Log messages into a file.
def set_logger(name, logfile=None):
    hostname = os.uname()[1]
    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)
    formatter = logging.Formatter(format)
    
    if DEBUG:
        logging.getLogger('').setLevel(logging.DEBUG)
    else:
        logging.getLogger('').setLevel(logging.INFO)
        
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)    
    
    if logfile:
        fileHandler = logging.FileHandler(logfile)
        fileHandler.setFormatter(formatter)
        logging.getLogger('').addHandler(fileHandler)

# Get the Wazuh API Token.
def get_token():
    request_result = requests.get(WAZUH_API + "/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY)

    if request_result.status_code == 200:
       token = json.loads(request_result.content.decode())['data']['token']
       HEADERS['Authorization'] = f'Bearer {token}'
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

# Get the list of agents.
def get_agents():
    agents_ids = []
    limit = 500
    offset = 0
    finish = False

    while not finish:
        agents_request = requests.get(WAZUH_API + f"/agents?limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

        if agents_request.status_code == 200:
            agents_list = json.loads(agents_request.content.decode())['data']

            for agent in agents_list['affected_items']:
                agents_ids.append(agent)

            # If there are more items to be gathered, iterate the offset
            if agents_list['total_affected_items'] > (limit + offset):
                offset = offset + limit

                if (offset + limit) > agents_list['total_affected_items']:
                    limit = agents_list['total_affected_items'] - offset

            else:
                finish = True

        else:
            if agents_request.status_code == 401:
                get_token() # Renew token

            else:
                raise Exception(f"Error obtaining response: {agents_request.json()}")

    return agents_ids

# Get agents' vulnerabilities and show/upload them.
def get_vulnerabilities(agents):
    limit = 400
    offset = 0
    finish = False
    counter = 0
    agent_vulnerabilities = []
    if ACTION == 'LOAD_CSV':
        print(f"({ACTION} to {CSV_FILE}) Getting the vulnerabilities of agent {agents['name']} (ID {agents['id']}).")
        logging.info(f"({ACTION} to {CSV_FILE}) Getting the vulnerabilities of agent {agents['name']} (ID {agents['id']}).")
    else:
        print(f"({ACTION}) Getting the vulnerabilities of agent {agents['name']} (ID {agents['id']}).")
        logging.info(f"({ACTION}) Getting the vulnerabilities of agent {agents['name']} (ID {agents['id']}).")

    while not finish:
        vulnerabilities_request = requests.get(WAZUH_API + f"/vulnerability/{agents['id']}?limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

        if vulnerabilities_request.status_code == 200:

            vulnerabilities_result = json.loads(vulnerabilities_request.content.decode())['data']

            for result in vulnerabilities_result['affected_items']:

                # Exclude duplicated package names as a package can have multiple CVEs
                if result['name'] not in agent_vulnerabilities:
                    agent_vulnerabilities.append(result['name'])

                # Create the log to be sent to the socket
                if result["status"] != "VALID":
                    return agent_vulnerabilities
                else:
                    alert = {
                        "vulnerability":{}
                    }
                alert["vulnerability"] = {
                    "type": result["type"],
                    "title": result["title"],
                    "detection_time": result["detection_time"],
                    "cve": result["cve"], 
                    "severity": result["severity"],
                    "status": 'Active'
                }
                
                if "external_references" in result:
                    alert['vulnerability']['external_references'] = result['external_references']            
                    
                alert['agent'] = {
                    "id":agents['id'],
                    "name":agents['name'],
                    "ip":agents['ip']
                }
                alert['rule'] = {
                    "description": result['title']
                }
                alert["vulnerability"]["package"] = {
                    "name": result["name"],
                    "version": result["version"],
                    "architecture": result["architecture"],
                    "condition": result["condition"]
                }
                if result['cvss2_score'] > 0:
                    alert['cvss'] = {}
                    alert['cvss']['cvss2'] = {}
                    alert['cvss']['cvss2'] = {
                        "base_score": result["cvss2_score"]
                    }
                if result['cvss3_score'] > 0:
                    alert['cvss'] = {}
                    alert['cvss']['cvss3'] = {}
                    alert['cvss']['cvss3'] = {
                       "base_score": result["cvss3_score"]
                    }
                counter += 1
                
                if ACTION == 'LOAD_CSV':
                    exportCSV(alert)
                elif ACTION == 'LOAD_ALERTS':
                    json_msg = json.dumps(alert, default=str)
                    send_event(json_msg)
                elif ACTION == 'WATCH_CSV':
                    line = f"{alert['agent']['name']}{CSV_CHAR}{alert['agent']['id']}{CSV_CHAR}{alert['agent']['ip']}{CSV_CHAR}{alert['vulnerability']['type']}{CSV_CHAR}{alert['rule']['description']}{CSV_CHAR}{alert['vulnerability']['detection_time']}{CSV_CHAR}{alert['vulnerability']['cve']}{CSV_CHAR}{alert['vulnerability']['severity']}{CSV_CHAR}{alert['vulnerability']['status']}{CSV_CHAR}{alert['vulnerability']['external_references']}{CSV_CHAR}{alert['package']['name']}{CSV_CHAR}{alert['package']['version']}{CSV_CHAR}{alert['package']['architecture']}{CSV_CHAR}{alert['package']['condition']}{CSV_CHAR}"
                    if counter == 1:                    
                        print(f'Agent{CSV_CHAR}Agent_ID{CSV_CHAR}Agent_IP{CSV_CHAR}Type{CSV_CHAR}Description{CSV_CHAR}Detection_Date{CSV_CHAR}CVE{CSV_CHAR}Severity{CSV_CHAR}Status{CSV_CHAR}External_References{CSV_CHAR}Package{CSV_CHAR}Pack_Version{CSV_CHAR}Pack_Arch{CSV_CHAR}Pack_Condition{CSV_CHAR}CVSS3_Score{CSV_CHAR}CVSS2_Score')
                    if "cvss" in alert:
                        if "cvss3" in alert['cvss']:
                            line = line + f"{alert['cvss']['cvss3']['base_score']}{CSV_CHAR}"
                        else:
                            line = line + f"-{CSV_CHAR}"
                        if "cvss2" in alert['cvss']:
                            line = line + f"{alert['cvss']['cvss2']['base_score']}"
                        else:
                            line = line + f"-"
                    else:
                        line = line + f"-{CSV_CHAR}-"
                    print(line)
                else:
                    json_msg = json.dumps(alert, default=str)
                    print(json_msg)

            # If there are more items to be gathered, iterate the offset
            if vulnerabilities_result['total_affected_items'] > (limit + offset):
                offset = offset + limit

                if (offset + limit) > vulnerabilities_result['total_affected_items']:
                    limit = vulnerabilities_result['total_affected_items'] - offset
            else:
                finish = True
        else:
            if vulnerabilities_request.status_code == 401:
                get_token() # Renew token
            else:
                if vulnerabilities_request.status_code == 400:
                    logging.error("The DB of agent " + str(agents['name']) + " (ID " + str(agents['id']) + ") is not available.")
                    return agent_vulnerabilities # No agent's DB found
                else:
                    raise Exception(f"Error obtaining response: {vulnerabilities_request.json()}")
        while vulnerabilities_request.status_code == 429:
            delay = 10
            logging.debug("Too many requests, delaying the request for {} seconds".format(str(delay)))
            time.sleep(delay)
            vulnerabilities_request = requests.get(WAZUH_API + f"/vulnerability/{agents['id']}?limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

    if ACTION == 'LOAD_CSV':
        print(f"({ACTION} to {CSV_FILE}) Finished getting the vulnerabilities of agent {agents['name']} (ID {agents['id']}). Total vulnerabilities: {counter}.")
        logging.info(f"({ACTION} to {CSV_FILE}) Finished getting the vulnerabilities of agent {agents['name']} (ID {agents['id']}). Total vulnerabilities: {counter}.")
    else:
        print(f"({ACTION}) Finished getting the vulnerabilities of agent {agents['name']} (ID {agents['id']}). Total vulnerabilities: {counter}.")
        logging.info(f"({ACTION}) Finished getting the vulnerabilities of agent {agents['name']} (ID {agents['id']}). Total vulnerabilities: {counter}.")
    time.sleep(sleepSec)
    return agent_vulnerabilities

# Generate CSV file
def exportCSV(event):
    line = f"{event['agent']['name']}{CSV_CHAR}{event['agent']['id']}{CSV_CHAR}{event['agent']['ip']}{CSV_CHAR}{event['vulnerability']['type']}{CSV_CHAR}{event['rule']['description']}{CSV_CHAR}{event['vulnerability']['detection_time']}{CSV_CHAR}{event['vulnerability']['cve']}{CSV_CHAR}{event['vulnerability']['severity']}{CSV_CHAR}{event['vulnerability']['status']}{CSV_CHAR}{event['vulnerability']['external_references']}{CSV_CHAR}{event['package']['name']}{CSV_CHAR}{event['package']['version']}{CSV_CHAR}{event['package']['architecture']}{CSV_CHAR}{event['package']['condition']}{CSV_CHAR}"
    if Path(CSV_FILE).is_file():
        with open(CSV_FILE, "a+") as csv_file:
            if LOGTEST:
                csv_file.write(f"{event['agent']['name']}{CSV_CHAR}{event['agent']['id']}{CSV_CHAR}{event['agent']['ip']}{CSV_CHAR}{event['vulnerability']['type']}{CSV_CHAR}{event['rule']['description']}{CSV_CHAR}{event['vulnerability']['detection_time']}{CSV_CHAR}{event['vulnerability']['cve']}{CSV_CHAR}{event['vulnerability']['severity']}{CSV_CHAR}{event['vulnerability']['status']}{CSV_CHAR}{event['vulnerability']['external_references']}{CSV_CHAR}{event['package']['name']}{CSV_CHAR}{event['package']['version']}{CSV_CHAR}{event['package']['architecture']}{CSV_CHAR}{event['package']['condition']}{CSV_CHAR}")
                if "cvss3" in event['cvss']:
                    csv_file.write(f"{event['cvss']['cvss3']['base_score']}{CSV_CHAR}")
                else:
                    csv_file.write("-{CSV_CHAR}")
                if "cvss2" in event['cvss']:
                    csv_file.write(f"{event['cvss']['cvss2']['base_score']}\n")
                else:
                    csv_file.write("-\n")
            else:
                csv_file.write(f"{event['agent']['name']}{CSV_CHAR}{event['agent']['id']}{CSV_CHAR}{event['agent']['ip']}{CSV_CHAR}{event['vulnerability']['type']}{CSV_CHAR}{event['rule']['description']}{CSV_CHAR}{event['vulnerability']['detection_time']}{CSV_CHAR}{event['vulnerability']['cve']}{CSV_CHAR}{event['vulnerability']['severity']}{CSV_CHAR}{event['vulnerability']['status']}{CSV_CHAR}{event['vulnerability']['external_references']}{CSV_CHAR}{event['package']['name']}{CSV_CHAR}{event['package']['version']}{CSV_CHAR}{event['package']['architecture']}{CSV_CHAR}{event['package']['condition']}{CSV_CHAR}")
                if "cvss" in event:
                    if "cvss3" in event['cvss']:
                        csv_file.write(f"{event['cvss']['cvss3']['base_score']}{CSV_CHAR}")
                    else:
                        csv_file.write(f"-{CSV_CHAR}")
                    if "cvss2" in event['cvss']:
                        csv_file.write(f"{event['cvss']['cvss2']['base_score']}\n")
                    else:
                        csv_file.write("-\n")
                else:
                    csv_file.write(f"-{CSV_CHAR}-\n")
    else:
        csv_file = open(str(CSV_FILE), 'w')
        if LOGTEST:
            csv_file.write(f'Agent{CSV_CHAR}Agent_ID{CSV_CHAR}Agent_IP{CSV_CHAR}Type{CSV_CHAR}Description{CSV_CHAR}Detection_Date{CSV_CHAR}CVE{CSV_CHAR}Severity{CSV_CHAR}Status{CSV_CHAR}External_References{CSV_CHAR}Package{CSV_CHAR}Pack_Version{CSV_CHAR}Pack_Arch{CSV_CHAR}Pack_Condition{CSV_CHAR}CVSS3_Score{CSV_CHAR}CVSS2_Score\n')
            csv_file.write(f"{event['agent']['name']}{CSV_CHAR}{event['agent']['id']}{CSV_CHAR}{event['agent']['ip']}{CSV_CHAR}{event['vulnerability']['type']}{CSV_CHAR}{event['rule']['description']}{CSV_CHAR}{event['vulnerability']['detection_time']}{CSV_CHAR}{event['vulnerability']['cve']}{CSV_CHAR}{event['vulnerability']['seventerity']}{CSV_CHAR}{event['vulnerability']['status']}{CSV_CHAR}{event['vulnerability']['external_references']}{CSV_CHAR}{event['package']['name']}{CSV_CHAR}{event['package']['version']}{CSV_CHAR}{event['package']['architecture']}{CSV_CHAR}{event['package']['condition']}{CSV_CHAR}")
            if "cvss3" in event['cvss']:
                csv_file.write(f"{event['cvss']['cvss3']['base_score']}{CSV_CHAR}")
            else:
                csv_file.write(f"-{CSV_CHAR}")
            if "cvss2" in event['cvss']:
                csv_file.write(f"{event['cvss']['cvss2']['base_score']}\n")
            else:
                csv_file.write("-\n")
        else:
            csv_file.write(f'Agent{CSV_CHAR}Agent_ID{CSV_CHAR}Agent_IP{CSV_CHAR}Type{CSV_CHAR}Description{CSV_CHAR}Detection_Date{CSV_CHAR}CVE{CSV_CHAR}Severity{CSV_CHAR}Status{CSV_CHAR}External_References{CSV_CHAR}Package{CSV_CHAR}Pack_Version{CSV_CHAR}Pack_Arch{CSV_CHAR}Pack_Condition{CSV_CHAR}CVSS3_Score{CSV_CHAR}CVSS2_Score\n')
            csv_file.write(f"{event['agent']['name']}{CSV_CHAR}{event['agent']['id']}{CSV_CHAR}{event['agent']['ip']}{CSV_CHAR}{event['vulnerability']['type']}{CSV_CHAR}{event['rule']['description']}{CSV_CHAR}{event['vulnerability']['detection_time']}{CSV_CHAR}{event['vulnerability']['cve']}{CSV_CHAR}{event['vulnerability']['severity']}{CSV_CHAR}{event['vulnerability']['status']}{CSV_CHAR}{event['vulnerability']['external_references']}{CSV_CHAR}{event['package']['name']}{CSV_CHAR}{event['package']['version']}{CSV_CHAR}{event['package']['architecture']}{CSV_CHAR}{event['package']['condition']}{CSV_CHAR}")
            if "cvss" in event:
                if "cvss3" in event['cvss']:
                    csv_file.write(f"{event['cvss']['cvss3']['base_score']}{CSV_CHAR}")
                else:
                    csv_file.write(f"-{CSV_CHAR}")
                if "cvss2" in event['cvss']:
                    csv_file.write(f"{event['cvss']['cvss2']['base_score']}\n")
                else:
                    csv_file.write("-\n")
    csv_file.close()

# Main function
def main():

    set_logger("vd_update", "/var/ossec/logs/vd_update.log")

    if WAZUH_AGENT != 'None':
        one_agent = {}
        # Get the token
        get_token()
        # Get list of agents.
        agents = get_agents()
        for agent in agents:
            if agent['id'] == WAZUH_AGENT:
                one_agent = {
                    'id': agent['id'],
                    'name': agent['name'],
                    'ip': agent['ip']
                }
                break

        if "name" in one_agent:
            get_vulnerabilities(one_agent)    
        else:
            print("ERROR! Agent ID: " + WAZUH_AGENT + " doesn't exists.")
        
    else:
        print("All agents selected!")
        # Get the token
        get_token()
        # Get Agents list
        agents = get_agents()
        for agent in agents:
            vulnerabilities_agent = get_vulnerabilities(agent)
            # If no vulnerabilities skip
            if not vulnerabilities_agent:
                continue
        
  
if __name__ == "__main__":
    
    set_logger("vd_update")
    
    # Parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--manager', type=str, default='127.0.0.1', help='*Wazuh API IP or DNS name.(def. "127.0.0.1").')
    parser.add_argument('-u', '--user', type=str, default='wazuh-wui', help='*Wazuh API user (def. "wazuh-wui").')
    parser.add_argument('-p', '--password', type=str, default='wazuh-wui', help='*Wazuh API user password (def. "wazuh-wui").')
    parser.add_argument('-port', '--port', type=str, default='55000', help='*Wazuh API port (def. 55000).')
    parser.add_argument('-a', '--agent', type=str, default='None', help='Specifies an AgentID (optional).')
    parser.add_argument('-w', '--write', type=bool, default=False, help='WARNING! WRITES data to a CSV file or Elastic(analysisd - optional).')
    parser.add_argument('-c', '--csv', type=str, default='NonE', help='Change format to CSV and indicates a filename. Uses \'|\' as a separator by default.')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    args = parser.parse_args()

    WAZUH_IP = args.manager
    WAZUH_USER = args.user
    WAZUH_PASS = args.password
    WAZUH_PORT = args.port
    WAZUH_AGENT = args.agent
    LOAD_DATA = args.write
    CSV_FILE = args.csv
    WAZUH_API=f"https://{WAZUH_IP}:{WAZUH_PORT}"
    if LOAD_DATA:
        if CSV_FILE != 'NonE':
            ACTION = 'LOAD_CSV'
        else:
            ACTION = 'LOAD_ALERTS'
    else:
        if CSV_FILE != 'NonE':
            ACTION = 'WATCH_CSV'

    main()
