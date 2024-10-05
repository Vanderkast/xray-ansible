# Vault secrets generation example

This example will show you how necessary secrets for Xray server and client are generated.

## Preparing vault 

It is expected that vault filled in with generated secrets is in YAML format.
`vault_secrets_generator.py` script looks through passed vault 

We start with `00_vault.yaml` file.

## Generating secrets

Run the following command to handle all placeholders in `00_vault.yaml` and write encrypted vault to `vault` file.

```shell
python ../../utils/secrets_generator.py vault \
    00_vault.yaml \
    -o vault \
    --no-decrypt \
    --password-file password \
    -v --log-secrets
```

Run the following command to print content of the encrypted `vault` file:
```shell
ansible-vault view vault --vault-password-file password
```
Output must be similar to the `01_vault.yaml` file content.