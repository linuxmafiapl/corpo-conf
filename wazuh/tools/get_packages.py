#!/var/ossec/framework/python/bin/python3

import requests, urllib3, sys, json, logging, os, argparse

HEADERS={}
VERIFY=False
# Disable warnings
requests.packages.urllib3.disable_warnings()

# Function to get the Wazuh API Token
def get_token():
    request_result = requests.get(WAZUH_API + "/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY)

    if request_result.status_code == 200:
       TOKEN = json.loads(request_result.content.decode())['data']['token']
       HEADERS['Authorization'] = f'Bearer {TOKEN}'
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

# Function to get the Agents
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

def get_packages(agents):
    limit = 2000
    offset = 0
    finish = False
    agent_packages = []

    while not finish:
        packages_request = requests.get(WAZUH_API + f"/syscollector/{agents['id']}/packages?limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

        if packages_request.status_code == 200:
        
            packages_result = json.loads(packages_request.content.decode())['data']
            
            if packages_result['total_affected_items'] == 0:
                print("No packages found for agent ID: " + agents['id'])
                return agent_packages
                
            for result in packages_result['affected_items']:
                print(json.dumps(result))
            
            # If there are more items to be gathered, iterate the offset
            if packages_result['total_affected_items'] > (limit + offset):
                offset = offset + limit

                if (offset + limit) > packages_result['total_affected_items']:
                    limit = packages_result['total_affected_items'] - offset
            else:
                finish = True
        else:
           if packages_request.status_code == 401:
               get_token() # Renew token
           else:
               if packages_request.status_code == 400:
                   print("There is no database for agent: " + agents['id'])
                   return agent_packages # No DB for agent

               else:
                   raise Exception(f"Error: {packages_request.json()}")
    if offset == 0:
        print("Agent: " + agents['name'] + " (ID:" + str(agents['id']) + ") - Total packages: " + str(packages_result['total_affected_items']))
    else:
        print("Agent: " + agents['name'] + " (ID:" + str(agents['id']) + ") - Total packages: " + str((offset+limit)))
    return agent_packages

def main():

    # Get the token
    get_token()

    # Get Agents list
    agents = get_agents()

    one_agent = {}

    # Get packages.
    if WAZUH_AGENT != 'None':
    	for agent in agents:
            if agent['id'] == WAZUH_AGENT:
            	one_agent = {
                	'id': agent['id'],
                	'name': agent['name'],
                	'ip': agent['ip']
            	}
            	break
	
    	if "name" in one_agent:
        	get_packages(one_agent)    
    	else:
        	print("ERROR! Agent ID: " + WAZUH_AGENT + " doesn't exists.")
    else:
        for agent in agents:        
            packages_agent = get_packages(agent)
            # If no packages skip
            if not packages_agent:
                continue
  
if __name__ == "__main__":
    
    # Parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--manager', type=str, default='127.0.0.1', help='Wazuh API server IP or DNS name.')
    parser.add_argument('-u', '--user', type=str, default='wazuh', help='Wazuh API user.')
    parser.add_argument('-p', '--password', type=str, default='wazuh', help='Wazuh API user password.')
    parser.add_argument('-port', '--port', type=str, default='55000', help='Wazuh API port.')
    parser.add_argument('-a', '--agent', type=str, default='None', help='Only checks packages for a specific agent.')
    args = parser.parse_args()

    WAZUH_IP = args.manager
    WAZUH_USER = args.user
    WAZUH_PASS = args.password
    WAZUH_PORT = args.port
    WAZUH_AGENT = args.agent
    WAZUH_API=f"https://{WAZUH_IP}:{WAZUH_PORT}"

    main()

