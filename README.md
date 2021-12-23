# vault-kv-search [![CircleCI](https://circleci.com/gh/cyrinux/vault-kv-search.svg?style=svg)](https://circleci.com/gh/cyrinux/vault-kv-search)

This tool is compatible with secrets kv v1 and v2.

This tool is compatible with secrets kv v1 and v2.

## Example Usage

- Export or prepend command with VAULT_ADDR and your VAULT_TOKEN

  ```
  > export VAULT_ADDR=https://vaultserver:8200
  > export VAULT_TOKEN=$(cat ~/.vault-token)
  ```

- Search values for the substring 'example.com':

  `> vault-kv-search secret/ example.com`

- Search keys for substring 'example.com':

  `> vault-kv-search --search=key secret/ example.com`

- Search keys and values for substring 'example.com':

  `> vault-kv-search --search=value --search=key secret/ example.com`

- Search secret name containing substring 'sshkeys':

  `> vault-kv-search --search=path secret/ sshkeys`

- To display the secrets, and not only the vault path, use the `--showsecrets` parameter.
