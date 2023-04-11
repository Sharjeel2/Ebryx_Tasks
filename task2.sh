#!/bin/bash

# Create and configure testroot user
echo -e "Creating new user 'testroot' and assigning it root privileges...\n"
adduser testroot
usermod -aG sudo testroot

# Switch to testroot user
echo -e "Switching to new user 'testroot'...\n"
su testroot << EOF

# Create and delete a file
echo -e "Creating a new file and deleting it...\n"
cd ~
touch test.txt
rm test.txt

# Start and stop a service/process
echo -e "Starting a process 'apache' and stopping it...\n"
systemctl start apache2
systemctl stop apache2

# Wget a file from github
echo -e "Downloading a file from github using wget...\n"
wget https://raw.githubusercontent.com/EbryxLabs/__DFIR-scripts/master/Excavator/Excavator.py

# Start ssh server
echo -e "Starting ssh server...\n"
systemctl start ssh

# Connect to remote server via ssh
echo -e "Connecting to a ssh server at a remote host and exiting...\n"
ssh stardust@172.25.200.130 << END

exit

END

# Create a file and share it over ssh with remote user
echo -e "Creating a new file and secure copying it over ssh to a remote host...\n"
echo "Testing!" > testFile.txt
scp testFile.txt stardust@172.25.200.130:/home/stardust/
exit

EOF

echo -e "Switching back to first user...\n"

# Create and configure testuser
echo -e "Creating a new user 'testuser' and switching to it...\n"
adduser testuser
su testuser << EOF

# Create a file and restrict its permissions to its owner only
echo -e "Creating a new file and restricting access to the onwer only...\n"
sudo touch test.txt
sudo chmod 700 test.txt
exit

EOF

echo "Switching back to first user and srcipt ends!"
