#!/bin/bash
#This script requires root permission

CURRENT_DATE=`date +"%Y-%m-%d"`
BACKUP_NAME="ruleset_backup"$CURRENT_DATE".tar.gz"
FEED_PATH="wazuh-feed.tar.gz"
LOCAL="no"
HASH_PATH="wazuh-feed_hash"
CDB="yes"
HASH="no"
TOKEN=""

help() {
    echo
    echo "Usage: $0 [OPTIONS] OR"
    echo "Usage: $0"
    echo "    -h, --help     [Optional] Show this help."
    echo "    -l PATH        [Optional] Set the path of the compressed local feed or backup."
    echo "    -s PATH        [Optional] Set the path of the feeds hash."
    echo "    -n             [Optional] Do the hash comprobation."
    echo "    -t TOKEN       [Required] Set the Token for download the Wazuh Feed."
    echo
    exit $1
}

while getopts ":hlt:s:n" opt; do
    case $opt in
        h) help 0 ;;
        l) FEED_PATH=$OPTARG
           LOCAL="yes";;
        s) HASH_PATH=$OPTARG ;;
        n) HASH="yes" ;;
        t) TOKEN=$OPTARG ;;
        :) echo "Missing argument for option -$OPTARG"; exit 1 ;;
       \?) echo "Unknown option -$OPTARG"; exit 1;;
    esac
done


# Step 0: Check that a token is provided

if [[ $TOKEN == "" ]]; then
  if [[ $LOCAL == "no" ]]; then
    echo "No token is provided"
    exit 5
  fi
fi

# Step 1: check the current installation

/var/ossec/bin/wazuh-analysisd -t
STATUS=$?
if [[ $STATUS -ne 0 ]] ; then
  read -p "Your installation seems to have present errors, do you still want to proceed? Y/N " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Nn]$ ]]
  then
      exit 1
  fi
fi


# Step 1.2: Check the dowloaded feed is the correct one
if [[ $LOCAL == "no" ]]; then
  curl -L -k -o $FEED_PATH "https://feed.owlh.net/feed/${TOKEN}/feed.tar.gz"
  curl -L -o $HASH_PATH 'https://docs.google.com/uc?export=download&id=1y_BXlcmtDAzdXikrfJq652Mb_9lxPXFT'
fi

if [[ $HASH == "yes" ]]; then
  md5sum $FEED_PATH > dowloaded_hash

  if cmp -s $HASH_PATH dowloaded_hash ; then
      echo "The downloaded feed is the correct one."
  else
      echo "Downloaded wrong Feed."
      rm $FEED_PATH $HASH_PATH dowloaded_hash
      exit 2
  fi
  rm dowloaded_hash
fi
rm $HASH_PATH


# Step 1.5: Check the feed with the current installation
mkdir /var/ossec/backup/test
cp /var/ossec/etc/ossec.conf /var/ossec/backup/test/ossec.conf
sed -i -r 's/<rule_dir>ruleset\/rules<\/rule_dir>/<rule_dir>backup\/test\/rules<\/rule_dir>/' /var/ossec/backup/test/ossec.conf
sed -i -r 's/<decoder_dir>ruleset\/decoders<\/decoder_dir>/<decoder_dir>backup\/test\/decoders<\/decoder_dir>/' /var/ossec/backup/test/ossec.conf
tar -zxf $FEED_PATH -C /var/ossec/backup/test
rm -rf /var/ossec/backup/test/tools

/var/ossec/bin/wazuh-analysisd -t -c backup/test/ossec.conf >> test.txt 2>&1
if grep -E 'WARNING:|ERROR:|CRITICAL:' test.txt ; then
  if grep -E 'WARNING:' test.txt ; then
    read -p "Your installation seems to have conflicts with the new feed, do you still want to proceed? Y/N " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]
    then
      if [[ $FEED_PATH == "feed.tar.gz" ]]; then
        rm $FEED_PATH
      fi
      rm test.txt
      exit 3
    fi
  fi
  if grep -E 'ERROR|CRITICAL' test.txt ; then
    echo "Your installation seems to have severe conflicts with the new feed, please fix them before continuing"
    rm test.txt
    if [[ $FEED_PATH == "feed.tar.gz" ]]; then
      rm $FEED_PATH
    fi
    exit 4
  fi
fi

# Step 2: Save the current ruleset

tar -czf /var/ossec/backup/${BACKUP_NAME} /var/ossec/ruleset/decoders /var/ossec/ruleset/rules /var/ossec/ruleset/sca /var/ossec/etc/lists
cp -a /var/ossec/etc/ossec.conf /var/ossec/backup/


# Step 3: stop the Wazuh manager

systemctl stop wazuh-manager

# Step 4: remove old ruleset

rm -rf /var/ossec/ruleset/decoders /var/ossec/ruleset/rules /var/ossec/ruleset/sca

# Step 5: deploy new ruleset

tar -zxf $FEED_PATH -C /var/ossec/ruleset
cp -r /var/ossec/ruleset/lists/* /var/ossec/etc/lists/
rm -rf /var/ossec/ruleset/lists
rm /var/ossec/backup/feed.*
mv $FEED_PATH /var/ossec/backup
rm /var/ossec/logs/ossec.log
touch /var/ossec/logs/ossec.log


# Step 5.1: Deploy new cdb
if [[ $CDB == "yes" ]] ; then
  sed -i -e '/<list>.*<\/list>/d' /var/ossec/etc/ossec.conf

  mv /var/ossec/etc/lists/lists.txt .

  sed -i '/<ruleset>/ r lists.txt'  /var/ossec/etc/ossec.conf
  rm lists.txt
fi
## Step 6: start the manager

systemctl start wazuh-manager
systemctl status wazuh-manager

# Step 7: Ensure new feed is healthy
rm test.txt
/var/ossec/bin/wazuh-analysisd -t -c backup/test/ossec.conf >> test.txt 2>&1
if grep -E 'WARNING|ERROR|CRITICAL' test.txt ; then
  read -p "The new feed seems to have errors or warnings, do you want to restore the previous ruleset? Y/N " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      systemctl stop wazuh-manager

      rm -rf /var/ossec/ruleset
      rm -rf /var/ossec/etc/lists
      rm /var/ossec/etc/ossec.conf
      tar -xzf /var/ossec/backup/${BACKUP_NAME} -C /home
      mv /home/var/ossec/ruleset /var/ossec/
      mv /home/var/ossec/etc/lists /var/ossec/etc
      mv /var/ossec/backup/ossec.conf /var/ossec/etc/ossec.conf
      rm -rf /home/var

      systemctl start wazuh-manager
      systemctl status wazuh-manager
  fi
fi

# Step 8: Remove evidences
rm /var/ossec/backup/ossec.conf
rm -rf /var/ossec/backup/test
rm test.txt
