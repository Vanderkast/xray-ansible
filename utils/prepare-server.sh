#!/usr/bin/env bash

#
# WARNING! Copy your ssh pub key to server root before use
#

# This script:
# - creates user with specified username and passoword.
# - copies all root authorized keys to created user
# - disables password ssh auth
#
# Use it like this:
# > ./utils/prepare-server.sh IP USERNAME


IP=$1
USERNAME=$2

echo -n Enter password for $USERNAME:
read -s PASSWORD
echo

prepare_server () {
    # Create user
    useradd -m -s /bin/bash -G sudo $USERNAME
    (echo $PASSWORD; echo $PASSWORD) | passwd $USERNAME

    # Copy root authorized keys to created user
    USER_SSH_DIR=/home/$USERNAME/.ssh/
    mkdir -p $USER_SSH_DIR
    cp -r /root/.ssh/authorized_keys $USER_SSH_DIR
    chown -R $USERNAME:$USERNAME $USER_SSH_DIR

    # Disable password auth
    sed -n -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -n -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config

    # Restart ssh deamon
    systemctl restart sshd
}

# Actually run preparation script on the remote server
ssh root@$IP "$(typeset -f prepare_server); USERNAME=$USERNAME PASSWORD=$PASSWORD prepare_server"