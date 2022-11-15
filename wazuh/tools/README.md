# The vd_update tool

 It can trigger alerts of last vulnerabilities found on the agents, it can create a CSV file with the vulnerabilities of one or all agents. Also can display on screen the vulnerabilities in the chosen format.

Improvements:

 - Now it can export data into CSV format.
 - Fixed error "too many requests per minute" issue.
 - Added a delay to avoid overloading the API (by default is 0.3 secs per agent).

DEFAULT ACTION now is WATCH, `it needs -w yes` parameter to write changes! (CSV file or alerts in Elastic).

Use cases:
`vd_update.py` // shows all the vulnes of all agents on screen in JSON format.
`vd_update.py -c agents` // shows all the vulnes of all agents in CSV format.
`vd_update.py -a 002` // shows all the vulnes of agent 002 in JSON format.
`vd_update.py -a 002 -c /home/john/002.csv -w yes` // WRITE all the vulnes from agent 002 in file /home/john/002.csv with CSV format.
`vd_update.py -c /agents.csv -w yes` // Loads all the vulnes from all agents into the file /agents.csv.

`vd_update.py -h`
```
usage: vd_update.py [-h] [-m MANAGER] [-u USER] [-p PASSWORD] [-port PORT] [-a AGENT] [-w WRITE] [-c CSV] [--debug]

optional arguments:
  -h, --help            show this help message and exit
  -m MANAGER, --manager MANAGER
                        *Wazuh API IP or DNS name.(def. "127.0.0.1").
  -u USER, --user USER  *Wazuh API user (def. "wazuh-wui").
  -p PASSWORD, --password PASSWORD
                        *Wazuh API user password (def. "wazuh-wui").
  -port PORT, --port PORT
                        *Wazuh API port (def. 55000).
  -a AGENT, --agent AGENT
                        Specifies an AgentID (optional).
  -w WRITE, --write WRITE
                        WARNING! WRITES data to a CSV file or Elastic(analysisd - optional).
  -c CSV, --csv CSV     Change format to CSV and indicates a filename. Uses '|' as a separator by default.
  --debug               Enable debug mode logging.
```


# The get_packages tool

 It gets the reported packages of one or all agents to Wazuh in a JSON format.

`get_packages.py -h`
```
usage: get_packages.py [-h] [-m MANAGER] [-u USER] [-p PASSWORD] [-port PORT] [-a AGENT]

optional arguments:
  -h, --help            shows this help message and exit
  -m MANAGER, --manager MANAGER
                        Wazuh API server IP or DNS name.
  -u USER, --user USER  Wazuh API user.
  -p PASSWORD, --password PASSWORD
                        Wazuh API user password.
  -port PORT, --port PORT
                        Wazuh API port.
  -a AGENT, --agent AGENT
                        Only checks packages for a specific agent.

```

# The vd_db_cleaner tool

 It cleans agents' internal db files and reset the vd flag to force a full_scan on the agents' side. 
 
 `# vd_db_cleaner.py`
 ```
 Cleaning vulnes and resetting LAST_FULL_SCAN of AgentID: 000
 Cleaning vulnes and resetting LAST_FULL_SCAN of AgentID: 001
 Cleaning vulnes and resetting LAST_FULL_SCAN of AgentID: 002
 Cleaning vulnes and resetting LAST_FULL_SCAN of AgentID: 004
 ```
