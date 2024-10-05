# XRay server setup

The goal of this project is to automate [XRay](https://github.com/XTLS/Xray-core) server setup.

For now, [vless-xray-xtls-reality](https://github.com/XTLS/Xray-examples/blob/main/VLESS-TCP-XTLS-Vision-REALITY/REALITY.ENG.md) combination can be configured only.

# Quick start

## Prerequisites

- Server with Ubuntu Linux (tested on v22.04) with public IP and accessible through ssh
- Python 3

## Step-by-step guide

This quide is written for Linux.

1. Clone the repository and navigate to the repository root directory.

2. (Optionally) you may want to create [python virtual environment](https://docs.python.org/3/library/venv.html).

3. Install python dependencies:
```bash
pip install -r requirements.txt
```

4. Install `libsodium` (required to generate Xray server key pair).

5. Copy quick_start_inventory from the examples directory to the repository root:
```shell
cp -r ./examples/quick_start_inventory ./inventories/
```

6. Update the following files content (there are comments that will help you) in the copied inventory:
- `hosts.yaml`
- `host_vars/quick/vars.yaml`
- `host_vars/quick/vault.yaml`

7. (Optionally) Create file `.vaultpassword`* and put there password that will be used to encrypt and decrypt your inventory's vaults: 
```shell
echo [PASSWORD] > ./inventories/quick_start_inventory/.vaultpassword 
```
\* Files with names `.password` and `.vaultpassword` are added to the [.gitignore](.gitignore) and will not be tracked by git.

8. Run `secrets_generator.py`* to replace placeholders in `./inventories/quick_start_inventory/host_vars/quick/vault.yaml` with corresponding secrets:
```shell
python ./utils/secrets_generator.py vault \
    --no-decrypt \
    ./inventories/quick_start_inventory/host_vars/quick/vault.yaml
```
\* add `--password-file ./inventories/quick_start_inventory/.vaultpassword` argument if you created password file at the step 7. Otherwise, you will be prompted to enter password for the vault

9. (Optional) If you use ssh key auth, [setup ssh-agent](https://docs.ansible.com/ansible/latest/inventory_guide/connection_details.html#setting-up-ssh-keys) to prevent ansible from asking for key.

10. Run Ansible setup playbook to install and configure Xray server:
```bash
ansible-playbook setup.yaml \
    -i ./inventories/quick_start_inventory/hosts.yaml
```

11. Configure clients. For now, there is no automated build configuration. Basically, every client must know:
- Server IP
- Server public key
- Server sid
- Client UUID


# Utils

Utils are a set of scripts and programs that can help with various tasks.

## secrets_generator.py

Secrets generator is a tool for Xray server and client secrets generation.
See help for details.

## prepare-server.sh

Prepare server script creates service user, disables ssh password auth and root login, 

# Implementation details

Under the hood an official [xray-install](https://github.com/XTLS/Xray-install) script is used.
