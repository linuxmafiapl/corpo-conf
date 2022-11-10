# **Wazuh**

Wazuh is a free and open source security platform that unifies XDR (Extended Detection and Response) and SIEM (Security Information and Event Management) capabilities. It protects workloads across on-premises, virtualized, containerized, and cloud-based environments.

## **Recommended Environment**

Ubuntu is recommended to deploy Wazuh Manager.

For lightweight deployment, use Ubuntu Server for less resource consumption on the OS.

## **Wazuh Installation (Version 4.3)**

### **Single Node Deployment**

Download the installer

```shell
curl -sO https://packages.wazuh.com/4.3/wazuh-install.sh
```

Execute the script

```shell
sudo bash ./wazuh-install.sh -a
```

After successfully running the script, an output containing the credentials to access Wazuh will be printed.

```bash
INFO: --- Summary ---
INFO: You can access the web interface https://<wazuh-dashboard-ip>
    User: admin
    Password: <ADMIN_PASSWORD>
INFO: Installation finished.
```

All the passwords can be printed with this command

```shell
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

### **Cluster Deployment**

Edit the configuration file in `/var/ossec/etc/ossec.conf` to configure the `<cluster>` block.

#### **Master Node**

The master node can be configured as follow:

```bash
<cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
    <key>GENERATED_KEY</key>
    <node_type>master</node_type>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>MASTER_IP_ADDRESS</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
</cluster>
```

- name: Set the name of the cluster.
- node-name: Set the name of the master node
- key: The key used must be 32 characters and the same key needs to be used across all nodes in the cluster. A key can be generated with the command:

  ```shell
  openssl rand -hex 16  
  ```

- node-type: Set the node type. (Master/Worker)
- port: Set the port used for cluster communication
- bind_addr: Set the IP address of what this node is listening to (Default is 0.0.0.0, meaning any IP)
- nodes: Set the IP address (or DNS name if any) of the master node. This must be specified in every node including the master node.
- hidden: Toggles whether or not to show information about the cluster that generated an alert.
- disabled: Indicates whether the node will be enabled or not in the cluster. Must be set to no if the node needs to be included in a cluster.

More information can be found [here](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#cluster).

Restart the master node:

```shell
sudo systemctl restart wazuh-manager
```

#### **Worker Node**

```bash
<cluster>
    <name>wazuh</name>
    <node_name>worker01-node</node_name>
    <key>GENERATED_KEY</key>
    <node_type>worker</node_type>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>MASTER_IP_ADDRESS</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
</cluster>
```

Restart the worker node:

```shell
sudo systemctl restart wazuh-manager
```

Run the following command to check if the configuration is correct:

```shell
sudo /var/ossec/bin/cluster_control -l
```

The expected output example:

```bash
NAME           TYPE    VERSION  ADDRESS
master-node    master  4.3.9   wazuh-master
worker01-node  worker  4.3.9   10.39.39.11
worker02-node  worker  4.3.9   10.39.39.12
```

### **Docker Deployment**

#### **Setup Docker**

##### **Set Container Memory**

Increase max_map_count on your host witht the following command:

```bash
sysctl -w vm.max_map_count=262144
```

Permenantly set the value by setting `vm.max_map_count=262144` in `/etc/sysctl.conf`.

> **Note:** If the max_map_count is not set, Wazuh Indexer will not function properly.

##### **Docker Engine**

Run Docker installation script

```bash
curl -sSL https://get.docker.com/ | sh
```

Start docker service

```bash
systemctl enable docker
systemctl start docker
```

##### **Docker Compose**

Download Docker Compose binary

```bash
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
```

Grant execution permissions

```bash
chmod +x /usr/local/bin/docker-compose
```

> **Note:** If docker-compose fail to start after installation, a symlink can be created.

```bash
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
```

Test if the installation is complete

```bash
docker-compose --version
```

#### **Single-Node Deployment**

Clone the repository

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.3.9 --depth=1
```

Change directory into `single-node`

```bash
cd wazuh-docker/single-node/
```

Generate certificates to secure traffic between nodes

```bash
docker-compose -f generate-indexer-certs.yml run --rm generator
```

Start Wazuh using docker-compose

```bash
docker-compose up -d
```

#### **Multi-Node Deployment**

Clone the repository

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.3.9 --depth=1
```

Change directory into `multi-node`

```bash
cd wazuh-docker/multi-node/
```

Generate certificates to secure traffic between nodes

```bash
docker-compose -f generate-indexer-certs.yml run --rm generator
```

Start Wazuh using docker-compose

```bash
docker-compose up -d
```

## **Wazuh Agent Installation**

### **Linux**

1. Access the Wazuh web interface
2. Go to Agents
3. Deploy new agents
4. Select and fill in the data according to the endpoint that needs to install Wazuh agent
5. Run the command shown in step 5 and 6

### **Windows**

#### **Installer**

The installer can be downloaded with the link at [Wazuh Agent Installer](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.9-1.msi)

#### **Powershell**

The same can be done at the [Linux](#linux) section in the powershell. Fill in the data with the Windows OS selected and copy the command into powershell to execute.

### **Agents In Cluster**

Pointing the agent to the cluster node

```bash

```

## **Features**

### **Active Reponse**

> **Configuration adding soon**

When specific requirements are satisfied, active responses use different countermeasures to handle current threats, such as limiting access to an agent from the threat source.

Active responses run a script in response to certain alerts being triggered based on the alert level or rule group. In response to a trigger, any number of scripts can be launched; however, these replies must be carefully evaluated. Poor rule and response implementation may enhance the system's susceptibility.

### **File Integrity Monitoring**

> **Configuration added soon**

Wazuh's File Integrity Monitoring (FIM) system monitors certain files and sends notifications when they are updated. The component in charge of this task is known as syscheck. This component maintains the cryptographic checksum and other information of files or Windows registry keys and compares them on a regular basis with the system's current files, looking for changes.

Real-time monitoring can be achieved by using the `realtime` attribite of FIM module.

### **Auditing Who-Data**

> **Configuration added soon**

This feature obtains information of who-data from monitored files. The information contains the user who made changes to the file and the program name or process used to carry them out.

### **Log Data Collection**

> **Configuration added soon**

The process of making sense of the records generated by servers or devices in real time is known as log data collection. Logs can be received by this component through text files or Windows event logs. It may also accept logs directly through remote syslog, which is handy for firewalls and other similar devices.

This process is designed to detect application or system faults, misconfigurations, intrusion attempts, policy violations, or security vulnerabilities.

### **Anomoly and Malware Detection**

> **Configuration added soon**

This process is designed to detect unexpected behavior in a system. When malware is installed in the system, it will try to modify the system to hide itself so the user cannot find or identify the malware. Wazuh will find the abnormal pattern that indicate potential intruders.

### **Vulnerabilities Detection**

> **Configuration added soon**

Wazuh is able to detect vulnerabilities in the applications installed on agents using the Vulnerability Detector module. This software audit is performed through the integration of vulnerability feeds indexed by Canonical, Debian, Red Hat, Arch Linux, ALAS (Amazon Linux Advisories Security), Microsoft, and the National Vulnerability Database.

### **VirusTotal Integration**

> **Configuration added soon**

Wazuh can scan monitored files for malicious content in monitored files. This solution is possible through an integration with VirusTotal, which is a powerful platform that aggregates multiple antivirus products along with an online scanning engine. Combining this tool with our FIM engine provides a simple means of scanning the files that are monitored to inspect them for malicious content.
