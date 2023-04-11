#!/bin/bash

# Create and configure testroot user
adduser testroot
usermod -aG sudo testroot

# Switch to testroot user
su testroot << EOF

# Create and delete a file
cd ~
touch test.txt
rm test.txt

# Start and stop a service/process
systemctl start apache2
systemctl stop apache2

# Wget a file from github
wget https://raw.githubusercontent.com/EbryxLabs/__DFIR-scripts/master/Excavator/Excavator.py

# Start ssh server
systemctl start ssh

# Connect to remote server via ssh
ssh stardust@172.25.200.130 << END

exit

END

# Create a file and share it over ssh with remote user
echo "Testing!" > testFile.txt
scp testFile.txt stardust@172.25.200.130:/home/stardust/
exit

EOF

# Create and configure testuser
adduser testuser
su testuser << EOF

# Create a file and restrict its permissions to its owner only
sudo touch test.txt
sudo chmod 700 test.txt
exit

EOF
