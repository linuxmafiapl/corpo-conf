**WAZUH AND DOMAIN STATS + ALIENVAULT OTX**
## 
## Intro

Wazuh和Domain Stats集成。通过Wazuh的active Response，根据AlienVault OTX IoCs检查新的、首次出现的或可疑的域名。

Wazuh 4.2大幅增强了active Response能力，超过了最初包含在OSSEC中的能力。现在，作为与代理的主动响应通信的一部分，触发响应的完整警报（JSON）可以传递给代理，而代理可以提取字段并将其作为命令执行的参数。

## Domain Stats

GitHub Repo [here](https://github.com/MarkBaggett/domain_stats)

Created by Mark Baggett (SANS instructor).

默认使用RDAP(Registration Data Access Protocol).

安装后，会下载 "top1m "并存储在其内部数据库（使用SQLite DB作为 "缓存 "）。

安装后，启用HTTP conns的监听器（默认端口为5730）。以主机名/域名为参数调用该API，将返回有价值的信息，用于威胁检测。


## AlienVault OTX

AlienVault Open Threat Exchange (OTX)。是一个基于社区的威胁情报。注册可以获得一个API key，允许每小时最多10,000个请求。
PS：需要注意的是，误报有点多。


## Workflow



### ossec.conf


```
<integration>
 <name>custom-dnsstats</name>
 <group>sysmon_event_22</group>
 <alert_format>json</alert_format>
</integration>
```


/var/ossec/integrations/


```
-rwxr-x--- 1 root ossec  1025 Oct 19 10:52 custom-dnsstats
-rwxr-x--- 1 root ossec  2772 Oct 20 07:34 custom-dnsstats.py
```


custom-dnsstats内容如下：


```
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac


${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
```


custom-dnsstats.py的内容如下：


```
#!/usr/bin/env python

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:dns_stats:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->dns_stats:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
false = False
alert_file = open(sys.argv[1])
alert = json.loads(alert_file.read())
alert_file.close()
alert_output = {}
# DNS Stats Base URL
dns_stats_base_url = 'http://127.0.0.1:5730/'
# Extract Queried Hostname from Sysmon Event
dns_query_name = alert["data"]["win"]["eventdata"]["queryName"]
dns_stats_url = ''.join([dns_stats_base_url, dns_query_name])
# DNS Stat API Call
try:
    dns_stats_response = requests.get(dns_stats_url)
except ConnectionError:
    alert_output["dnsstat"] = {}
    alert_output["integration"] = "dnsstat"
    alert_output["dnsstat"]["error"] = 'Connection Error to DNS Stats API'
    send_event(alert_output, alert["agent"])
else:
    dns_stats_response = dns_stats_response.json()
# Check if response includes alerts or New Domain
    if (dns_stats_response["alerts"] and dns_stats_response["category"] != 'ERROR') or  dns_stats_response["category"] == 'NEW':
# Generate Alert Output from DNS Stats Response
        alert_output["dnsstat"] = {}
        alert_output["integration"] = "dnsstat"
        alert_output["dnsstat"]["query"] = dns_query_name
        alert_output["dnsstat"]["alerts"] = dns_stats_response["alerts"]
        alert_output["dnsstat"]["category"] = dns_stats_response["category"]
        alert_output["dnsstat"]["freq_score"] = dns_stats_response["freq_score"]
        alert_output["dnsstat"]["seen_by_isc"] = dns_stats_response["seen_by_isc"]
        alert_output["dnsstat"]["seen_by_web"] = dns_stats_response["seen_by_web"]
        alert_output["dnsstat"]["seen_by_you"] = dns_stats_response["seen_by_you"]
        send_event(alert_output, alert["agent"])
```


检测规则：dns_stats.xml


```
<group name="dnsstat,">
 <rule id="100010" level="5">
    <field name="integration">dnsstat</field>
    <description>DNS Stats</description>
    <options>no_full_log</options>
    <group>dnsstat_alert,</group>
  </rule>
<rule id="100011" level="5">
    <if_sid>100010</if_sid>
    <field name="dnsstat.alerts">LOW-FREQ-SCORES|SUSPECT-FREQ-SCORE</field>
    <description>DNS Stats - Low Frequency Score in Queried Domain</description>
    <mitre>
     <id>T1071</id>
    </mitre>
    <options>no_full_log</options>
    <group>dnsstat_alert,</group>
  </rule>

<rule id="100012" level="5">
    <if_sid>100010</if_sid>
    <field name="dnsstat.alerts">YOUR-FIRST-CONTACT</field>
    <description>DNS Stats - Domain Queried for the first time</description>
    <mitre>
     <id>T1071</id>
    </mitre>
    <options>no_full_log</options>
    <group>dnsstat_alert,</group>
  </rule>
<rule id="100013" level="5">
      <if_sid>100010</if_sid>
      <field name="dnsstat.category">NEW</field>
      <description>DNS Stats - DNS Query to Recently Created Domain</description>
      <mitre>
       <id>T1071</id>
      </mitre>
      <options>no_full_log</options>
      <group>dnsstat_alert,</group>
    </rule>
<rule id="100014" level="5">
    <if_sid>100010</if_sid>
    <field name="dnsstat.error">\.+</field>
    <description>DNS Stats - Error connecting to API</description>
    <options>no_full_log</options>
    <group>dnsstat_error,</group>
  </rule>
</group>

```


告警示例：


```
{
  "timestamp":"2022-10-20T07:59:10.937+1100",
  "rule":{
     "level":5,
     "description":"DNS Stats - Domain Queried for the first time",
     "id":"100012",
     "firedtimes":1,
     "mail":false,
     "groups":[
        "dnsstat",
        "dnsstat_alert"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1634677150.218702128",
  "decoder":{
     "name":"json"
  },
  "data":{
     "dnsstat":{
        "query":"elconfidencial.com",
        "alerts":[
           "YOUR-FIRST-CONTACT"
        ],
        "category":"ESTABLISHED",
        "freq_score":[
           6.6079,
           6.0942
        ],
        "seen_by_isc":"RDAP",
        "seen_by_web":"Tue, 19 Sep 2000 15:00:50 GMT",
        "seen_by_you":"Tue, 19 Oct 2022 20:59:08 GMT"
     },
     "integration":"dnsstat"
  },
  "location":"dns_stats"
}
```


告警示例（Low Frequency Score）


```
{
  "timestamp":"2022-10-20T07:58:18.453+1100",
  "rule":{
     "level":5,
     "description":"DNS Stats - Low Frequency Score in Queried Domain",
     "id":"100011",
     "firedtimes":1,
     "mail":false,
     "groups":[
        "dnsstat",
        "dnsstat_alert"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1634677098.218295676",
  "decoder":{
     "name":"json"
  },
  "data":{
     "dnsstat":{
        "query":"yt3.ggpht.com",
        "alerts":[
           "LOW-FREQ-SCORES"
        ],
        "category":"ESTABLISHED",
        "freq_score":[
           4.0377,
           3.871
        ],
        "seen_by_isc":"top1m",
        "seen_by_web":"Wed, 16 Jan 2008 18:55:33 GMT",
        "seen_by_you":"Mon, 18 Oct 2022 22:17:34 GMT"
     },
     "integration":"dnsstat"
  },
  "location":"dns_stats"
}
```


ALIENVAULT OTX Integration:

Command and Active Response:


```
<command>
    <name>alienvault_otx</name>
    <executable>otx.cmd</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
 <active-response>
   <disabled>no</disabled>
   <level>3</level>
   <command>alienvault_otx</command>
   <location>local</location>
   <rules_group>dnsstat_alert</rules_group>
  </active-response>
```


在windows机器中，需要在/active-response/bin目录下创建一个名为 “otx.cmd” 的文件：


```
:: Simple script to run AlienVault OTX PShell script.
:: The script executes a powershell script and appends output.
@ECHO OFF
ECHO.

"C:\Program Files\PowerShell\7\"pwsh.exe -executionpolicy ByPass -File "c:\Program Files\Sysinternals\otx.ps1"

:Exit
```
注意：需要Powershell 7.x，用户正确解析JSON输入，以及文件 "otx.ps1"（在本例中，放置在sysinternals文件夹中），如下，放在机器中的哪个目录下都可以。



```
$otxkey = "Your_API_KEY"
# Read the Alert that triggered the Active Response in manager and convert to Array
$INPUT_JSON = Read-Host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json 
$INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json 

#Function to Call OTX API with Params and Return Response
function ApiCall($indicator_type, $param) {
  $url = "https://otx.alienvault.com/api/v1/indicators/$indicator_type/$param/general"
  $otx_response = invoke-webrequest -URI $url -UseBasicParsing -Headers @{"X-OTX-API-KEY"="$otxkey"} -UseDefaultCredentials
  if (($otx_response.StatusCode -eq '200') -And (select-string -pattern '\"username\":\ \"AlienVault\"' -InputObject $otx_response.content))
  {
#Convert Response (JSON) to Array and remove objects
    $otx_response_array = $otx_response | ConvertFrom-Json
    $otx_response_array_trim = $otx_response_array | Select-Object sections,type,base_indicator
#Append Alert to Active Response Log
    echo  $otx_response_array_trim | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
  }
}
#Switch For Rule Group From Alert
$switch_condition = ($INPUT_ARRAY."parameters"."alert"."rule"."groups"[1]).ToString()
switch -Exact ($switch_condition){
#If Rule Group = "dnsstat_alert", Extract queried hostname and call the API
#Alert example: {"timestamp":"2021-10-20T05:12:39.783+1100","rule":{"level":5,"description":"DNS Stats - New or Low Frequency Domain Detetcted in Query","id":"100010","firedtimes":2,"mail":false,"groups":["dnsstat","dnsstat_alert"]},"agent":{"id":"034","name":"WIN-7FK8M79Q5R6","ip":"192.168.252.105"},"manager":{"name":"tactical"},"id":"1634667159.125787496","decoder":{"name":"json"},"data":{"dnsstat":{"query":"yt3.ggpht.com","alerts":["LOW-FREQ-SCORES"],"category":"ESTABLISHED","freq_score":[4.0377,3.871],"seen_by_isc":"top1m","seen_by_web":"Wed, 16 Jan 2008 18:55:33 GMT","seen_by_you":"Mon, 18 Oct 2021 22:17:34 GMT"},"integration":"dnsstat"},"location":"dns_stats"}
"dnsstat_alert"
    {
       $indicator_type = 'hostname'
       $hostname = $INPUT_ARRAY."parameters"."alert"."data"."dnsstat"."query"
       ApiCall $indicator_type $hostname  
    break;
    } 
    
}
######################
## Wazuh Manager: Command and AR.
# <command>
#    <name>alienvault_otx</name>
#    <executable>otx.cmd</executable>
#    <timeout_allowed>no</timeout_allowed>
#  </command>
####################
# <active-response>
#   <disabled>no</disabled>
#   <level>3</level>
#   <command>alienvault_otx</command>
#   <location>local</location>
#   <rules_group>dnsstat_alert</rules_group>
#  </active-response>
```


检测规则：alienvault_otx_rules.xml


```
<group name="alienvault,">
<rule id="91580" level="12">
  <decoded_as>json</decoded_as>
  <field name="sections">\.+</field>
  <field name="type">\.+</field>
  <description>AlienVault OTX -Indicator(s) Found</description>
  <mitre>
   <id>T1036</id>
  </mitre>
  <options>no_full_log</options>
  <group>otx_ioc,</group>
</rule>
</group>
```


告警示例：


```
{
  "timestamp":"2022-10-20T08:38:46.846+1100",
  "rule":{
     "level":12,
     "description":"AlienVault OTX -Indicator(s) Found",
     "id":"91580",
     "mitre":{
        "id":[
           "T1036"
        ],
        "tactic":[
           "Defense Evasion"
        ],
        "technique":[
           "Masquerading"
        ]
     },
     "firedtimes":1,
     "mail":true,
     "groups":[
        "alienvault",
        "otx_ioc"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1634679526.237987400",
  "decoder":{
     "name":"json"
  },
  "data":{
     "sections":[
        "general",
        "geo",
        "url_list",
        "passive_dns",
        "malware",
        "whois",
        "http_scans"
     ],
     "type":"hostname",
     "base_indicator":{
        "id":"2582882147.000000",
        "indicator":"www.mlcrosoft.site",
        "type":"hostname",
        "access_type":"public"
     }
  },
  "location":"active-response\\active-responses.log"
}
```

