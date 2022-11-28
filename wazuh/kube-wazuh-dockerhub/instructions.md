# Usage

This guide describes the necessary steps to deploy Wazuh on Kubernetes.

## Pre-requisites

- Kubernetes cluster already deployed.

## Deploy

### Step 1: Deploy Kubernetes

Deploying the Kubernetes cluster is out of the scope of this guide.

### Step 2: Deployment

Clone / download this repository

### Step 2.1: Setup SSL certificates

You can generate self-signed certificates for the Wazuh by running both:
/certs/indexer_cluster/_generate_certs.sh
/certs/reverse-proxy/_generate_certs.sh

### Step 2.2: Apply all manifests using kustomize

Start
```BASH
$ kubectl apply -k envs/local/
```

Stop
```BASH
$ kubectl delete -k envs/local/
```

#### Step 3 : Access Wazuh dashboard

=> https://wazuzh.kube.local
(Do not forget to add in /etc/hosts : 127.0.0.1 https://wazuzh.kube.local)
