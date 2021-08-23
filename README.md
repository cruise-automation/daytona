[![Testing](https://github.com/cruise-automation/daytona/actions/workflows/main.yml/badge.svg)](https://github.com/cruise-automation/daytona/actions/workflows/main.yml)

![DAYTONA](project/images/logo.png)

This is intended to be a lighter, alternative, implementation of the Vault client CLI primarily for services and containers. Its core features are the ability to automate authentication, fetching of secrets, and automated token renewal.

Previously authentication to, and secret retrieval from, Vault via a server or container was a delicate balance of shell scripts or potentially lengthy http implementations, similar to:

```shell
vault login -token-only -method=$METHOD role=$VAULT_ROLE"
THING="$(vault read -field=key secret/path/to/thing)"
ANOTHER_THING="$(vault read -field=key secret/path/to/another/thing)"
echo $THING | app
...
```

Instead, a single binary can be used to accomplish most of these goals.

* [Authentication](#authentication)
* [Secret Fetching](#secret-fetching)
* [Implementation Examples](#implementation-examples)
* [Development](#development)
* [Usage](#usage)
  + [Deployment](#deployment)
* [License](#license)
* [Contributions](#contributions)

### Authentication

The following authentication methods are supported:

 - **Kubernetes** - To be used with the [Vault Kubernetes Auth Backend](https://www.vaultproject.io/docs/auth/kubernetes.html). Uses the JWT of the bound kubernetes service account as described in the official Vault documentation. Intended for use as an `initContainer`, sidecar container, or entrypoint; for managing secrets within a pod.

 - **AWS IAM** - To be used with the [Vault AWS Auth Backend](https://www.vaultproject.io/docs/auth/aws.html). Uses the IAM Role for Vault authentication. Intended for use on AWS resources that utilize IAM roles.

 - **GCP IAM** - To be used with the [Vault GCP Auth Backend](https://www.vaultproject.io/docs/auth/gcp.html). Uses GCP service accounts for IAM Vault authentication. Intended for use with GCP resources that utilize bound service accounts.

 - **Azure IAM** - To be used with the [Vault Azure Auth Backend](https://www.vaultproject.io/docs/auth/azure.html). Uses Azure Active Directory credentials for IAM Vault authentication. Intended for use with Azure resources that utilize manged identities.

----

## Secret Fetching

`daytona` gives you the ability to pre-fetch secrets upon launch and store them either in environment variables, as JSON to a specified file, or as singular secrets to a specified file. You define what secrets should be fetched by supplying one or more **Secret Definitions**. Secret Definitions are supplied via environment variables.

**Secret Definition Decoder Guide**

`<STORAGE PATH PREFIX>_<secretID-SUFFIX>=<SECRET-APEX>`

- `VAULT_SECRET_` (`<STORAGE PATH PREFIX>`): Singular Secret Storage Path Prefix
- `VAULT_SECRETS_` (`<STORAGE PATH PREFIX>`): Plural (more than 1 secret beneath the specified path) Secret Storage Path Prefix
- `secretID-SUFFIX`: The unique secret identifier that can be used to tie a Secret Storage Path Prefix to a corresponding Destination Prefix. The uniqueness of this value provides the ability to supply multiple secret paths.
- `SECRET-APEX`: When used with **Singular** definitions, the Vault path where the secret exists in Vault that can be read. When used with **Plural** definitions, the Vault path where the secrets exist in Vault that can be listed and then read. This will fetch all secrets within the given Vault directory.

**Secret Definition Options**

- `DAYTONA_SECRET_DESTINATION_`: Secret Destination Prefix. This is a full file path location where the corresponding secret from the supplied storage path is written to. Usage: `DAYTONA_SECRET_DESTINATION_<secretID-SUFFIX>=/path/to/file`
- `VAULT_VALUE_KEY_`: Can be used to indicate the retrieval of a single key from a singular secret definition. Usage: `VAULT_VAULT_KEY_<secretID-SUFFIX>=api_key`

**Singular Secrets**
- Singular Secret Declaration: `VAULT_SECRET_<secretID-SUFFIX>=<SECRET-APEX>`
- Singular Secret Destination: `DAYTONA_SECRET_DESTINATION_<secretID-SUFFIX>=<FILE-PATH>`

**Plural Secrets**
- Plural Secret Declaration: `VAULT_SECRETS_<secretID-SUFFIX>=<SECRET-APEX>`
- Singular Secret Destination: `DAYTONA_SECRET_DESTINATION_<secretID-SUFFIX>=<FILE-PATH>`

---

### Examples

**Singular Secret**

Vault Data

```shell
$ vault read secret/whatever/thing

Key                 Value
---                 -----
refresh_interval    768h
value               hello
```

Secret Definition

```shell
VAULT_SECRET_THING=secret/whatever/thing
DAYTONA_SECRET_DESTINATION_THING=/tmp/top-secret
```

Result

`hello` would be written to the file `/tmp/top-secret`

---

**Singular Secret w/Specific Key**

Vault Data

```shell
$ vault read secret/whatever/thing

Key                 Value
---                 -----
refresh_interval    768h
value               hello
api_key             potato1234
```

Secret Definition

```shell
VAULT_SECRET_THING=secret/whatever/thing
DAYTONA_SECRET_DESTINATION_THING=/tmp/top-secret
VAULT_VALUE_KEY_THING=api_key
```

Result

`potato1234` would be written to the file `/tmp/top-secret`

---

**Plural Secrets**

Vault Data

```shell
$ vault list secret/many

Keys
----
thing1
thing2
thing3

$ vault read secret/many/thing1

Key                 Value
---                 -----
refresh_interval    768h
value               1

etc...
```

Secret Definition

```shell
VAULT_SECRETS_THING=secret/many
DAYTONA_SECRET_DESTINATION_THING=/tmp/top-secret-many
```

Result

`/tmp/top-secret-many` would be populated with:

```json
{
  "thing1": "1",
  "thing2": "2",
  "thing3": "3"
}
```


#### Outputs

Fetched secrets can be output via the following methods:

- `DAYTONA_SECRET_DESTINATION_` The secret destination prefix as specified above
- Environment variables via `-secret-env`. Because docker containers cannot set each other's environment variables, `-secret-env` will have no effect unless used with the `-entrypoint` flag, so that any populated environment variables are passed to a provided executable.
- `-secret-path` **(Deprecated)** Specifies a file which to output a JSON representation of a fetched secret(s)


#### Data and Secret Key Layout

`daytona` prefers secret data containing the key `value`, but is able to detect other key names (this decreases readability, as you'll see later below). For example:

the secret `secret/path/to/database` should have its data stored as:

```json
{
  "value": "databasepassword"
}
```

If `-secret-env` is supplied at runtime, the above example would be written to an environment variable as `DATABASE=databasepassword`, while `DAYTONA_SECRET_DESTINATION_PATH=/tmp/secrets` would be written to a file as:

```json
{
  "database": "password"
}
```

If data within a secret is stored as multiple key-values, which is the **`non-preferred`** format, then the secret data will be stored as a combination of `SECRETNAME_DATAKEYNAME=value`. For example, if the Vault secret `secret/path/to/database` has multiple key-values:

```json
{
  "db_username": "foo",
  "db_password": "databasepassword"
}
```

then a secret's data will be fetched by `daytona`, and stored as variables `DATABASE_DB_USERNAME=foo` and `DATABASE_DB_password=databasepassword`, or respectively, written to a file as:

```json
{
  "database_db_username": "foo",
  "database_db_password": "databasepassword"
}
```


### Supported Paths

**Top Level Path Iteration**

Consider the following path, `secret/path/to/directory` which when listed, contains the following secrets:

```
database
api_key
moredatahere/
```

`daytona` would iterate through all of these values attempting to read their secret data. Because `moredatahere/` is a subdirectory in a longer path, it would be skipped.


**Direct Path**

If provided a direct path `secret/path/to/database`, `daytona` will process secret data as outlined in the **Data and Secret Key Layout** section above.

----

## Implementation Examples

You have configured a vault k8s auth role named `awesome-app-vault-role-name` that contains the following configuration:

```
{
  "bound_service_account_names": [
    "awesome-app"
  ],
  "bound_service_account_namespaces": [
    "elite-squad"
  ],
  "policies": [
    "too-permissive"
  ],
  "ttl": 3600
}
```

**K8s Pod Definition Example**:

Be sure to populate the `serviceAccountName` and `VAULT_AUTH_ROLE` with the corresponding values from your vault k8s auth role as described above.

```yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: awesome-app
spec:
  serviceAccountName: awesome-app
  volumes:
    - name: vault-secrets
      emptyDir:
        medium: Memory
  initContainers:
    - name: daytona
      image: gcr.io/supa-fast-c432/daytona@sha256:abcd123
      securityContext:
        runAsUser: 9999
        allowPrivilegeEscalation: false
      volumeMounts:
      - name: vault-secrets
        mountPath: /home/vault
      env:
      - name: K8S_AUTH
        value: "true"
      - name : K8S_AUTH_MOUNT
        value: "kubernetes-gcp-dev-cluster"
      - name: SECRET_ENV
        value: "true"
      - name: TOKEN_PATH
        value: /home/vault/.vault-token
      - name: VAULT_AUTH_ROLE
        value: awesome-app-vault-role-name
      - name: DAYTONA_SECRET_DESTINATION_PATH
        value: /home/vault/secrets
      - name: VAULT_SECRETS_PATH
        value: secret/path/to/app
      - name: VAULT_SECRETS_GLOBAL
        value: secret/path/to/global/metrics
````

Note the `securityContext` provided above. Without it, the daytona container runs as UID 0, which is root. Because daytona writes files with `0600` permissions, the files are only readable by a user with the same UID. It is necessary to run your other containers in the pod with the same `securityContext` in order to read the files that daytona places.

The example above, assuming a successful authentication, would yield a vault token at `/home/vault/.vault-token` and any specified secrets written to `/home/vault/secrets` as

```json
{
  "api_key": "supersecret",
  "database": "databasepassword",
  "metrics": "helloworld"
}
```

the secrets written above would be the representation of the following vault data:

`secret/path/to/app/api_key`

```json
{
  "value": "supersecret"
}
```

`secret/path/to/app/database`

```json
{
  "value": "databasepassword"
}
```

`secret/path/to/global/metrics`

```json
{
  "value": "helloworld"
}
```


**AWS IAM Example - Writing to a File**:

Assume you have the following Vault AWS Auth Role, `vault-role-name`:

```json
{
  "auth_type": "iam",
  "bound_iam_principal_arn": [
    "arn:aws:iam::12345:role/my-role"
  ],
  "policies": [
    "my-ro-policy"
  ]
}
```

```
VAULT_SECRETS_TEST=secret/path/to/app/secrets DAYTONA_SECRET_DESTINATION_TEST=/home/vault/secrets daytona -iam-auth -token-path /home/vault/.vault-token -vault-auth-role vault-role-name
```

The execution example above (assuming a successful authentication) would yield a vault token at `/home/vault/.vault-token` and any specified secrets written to `/home/vault/secrets` as

```json
{
  "secrets_secretA": "hellooo",
  "secrets_api_key": "supersecret"
}
```

as a representation of the following vault data:

`secret/path/to/app/secrets`

```
{
  "secretA": "hellooo",
  "api_key": "supersecret"
}
```

**AWS IAM Example - As a container entrypoint**:

In a `Dockerfile`:

```dockerfile
ENTRYPOINT [ "./daytona", "-secret-env", "-iam-auth", "-vault-auth-role", "vault-role-name", "-entrypoint", "--" ]
```

combined with supplying the following during a `docker run`:

`-e "VAULT_SECRETS_APP=secret/path/to/app"`

would yield the following environment variables in a container:

```ini
API_KEY=supersecret
DATABASE=databasepassword
```

as a representation of the following vault data:

`secret/path/to/app/api_key`

```json
{
  "value": "supersecret"
}
```

`secret/path/to/app/database`

```json
{
  "value": "databasepassword"
}
```

**AWS IAM Example - As a container entrypoint, for requesting a PKI certificate**:

In a `Dockerfile`:

```dockerfile
ENTRYPOINT [ "./daytona", "-iam-auth", "-vault-auth-role", "vault-role-name", "-pki-issuer", "pki-backend", "-pki-role", "my-role", "-pki-domains", "www.example.com", "-pki-cert", "/etc/cert.pem", "-pki-privkey", "/etc/key.pem", "-pki-use-ca-chain", -entrypoint", "--" ]
```

Given a PKI backend issuer role located at `pki-backend/issue/my-role`, and `update` permissions granted to `vault-role-name` on this path, Daytona will request a certificate for `www.example.com` from Vault, placing the certificate (with CA chain) and private key in `/etc`.

N.b.:
* The role should have `www.example.com` configured in its `allowed_domains`
* Before setting `-pki-use-ca-chain`, verify whether the PKI backend in question has the full chain at `<pki-backend>/ca_chain`
  - Some Vault PKI backends may have the full chain (including the root), while others may only have the intermediates.
  - Services using this cert/chain may refuse to accept a cert with the root in the chain - use with caution.


**GCP GCE Example - Writing to a File**:

Assume you have the following Vault GCP Auth Role:

```json
{
    "bound_projects": [
        "my-project"
    ],
    "bound_service_accounts": [
        "cruise-automation-sa@my-project.iam.gserviceaccount.com"
    ],
    "policies": [
        "my-ro-policy"
    ],
    "type": "iam"
}
```

```
VAULT_SECRETS_TEST=secret/path/to/app/secrets DAYTONA_SECRET_DESTINATION_TEST=/home/vault/secrets daytona -gcp-auth -gcp-svc-acct cruise-automation-sa@my-project.iam.gserviceaccount.com -token-path /home/vault/.vault-token -vault-auth-role vault-gcp-role-name
```

The execution example above (assuming a successful authentication) would yield a vault token at `/home/vault/.vault-token` and any specified secrets written to `/home/vault/secrets` as

```json
{
  "secrets_secretA": "hellooo",
  "secrets_api_key": "supersecret"
}
```

as a representation of the following vault data:

`secret/path/to/app/secrets`

```json
{
  "secretA": "hellooo",
  "api_key": "supersecret"
}
```

**Security Consideration** - When using the GCP IAM Auth type, ensure that the capability for the GCP SA to use the `signjwt` permission is limited only to the service accounts you wish to authenticate with to Vault. Providing your GCP SA the `signjwt` permission, such as through `iam.serviceAccountTokenCreator`, when done at the project level will over-authorize your service account to be able to sign JWTs of any other service account in the project, thus impersonating them. It is best practice to bind these permissions against the service account itself, and not at the project level. For more information, see the [GCP Documentation](https://cloud.google.com/iam/docs/granting-roles-to-service-accounts#granting_access_to_a_service_account_for_a_resource) on how to grant permissions against a specific service account.

**Azure IAM Example - Writing to a File**:

Assume you have the following [Vault Azure Auth Role](https://www.vaultproject.io/api/auth/azure#create-role), `vault-role-name`:

```json
{
  "bound_subscription_ids": [
     "00000000-0000-0000-0000-000000000000"
  ],
  "token_policies": [
    "my-ro-policy"
  ]
}
```

```
VAULT_SECRETS_TEST=secret/path/to/app/secrets DAYTONA_SECRET_DESTINATION_TEST=/home/vault/secrets daytona -azure-auth -token-path /home/vault/.vault-token -vault-auth-role vault-role-name
```

The execution example above (assuming a successful authentication) would yield a vault token at `/home/vault/.vault-token` and any specified secrets written to `/home/vault/secrets` as

```json
{
  "secrets_secretA": "hellooo",
  "secrets_api_key": "supersecret"
}
```

as a representation of the following vault data:

`secret/path/to/app/secrets`

```
{
  "secretA": "hellooo",
  "api_key": "supersecret"
}
```

Development
-----------

### Building

Building is easy to do. Make sure to setup your local environment according to
https://golang.org/doc/code.html. Once setup, you should be able to build the
binaries using the following command:

```
make build
```

Tests are run via:

```
make test
```

Usage
-----

#### Usage Example

```
Usage of ./daytona:
  -address string
      Sets the vault server address. The default vault address or VAULT_ADDR environment variable is used if this is not supplied
  -auth-mount string
  -auto-renew
      if enabled, starts the token renewal service (env: AUTO_RENEW)
  -aws-auth
      select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)
  -entrypoint
      if enabled, execs the command after the separator (--) when done. mostly useful with -secret-env (env: ENTRYPOINT)
  -gcp-auth
      select Google Cloud Platform IAM auth as the vault authentication mechanism (env: GCP_AUTH)
  -gcp-auth-mount string
      the vault mount where gcp auth takes place (env: GCP_AUTH_MOUNT) (default "gcp")
  -gcp-svc-acct string
      the name of the service account authenticating (env: GCP_SVC_ACCT)
  -iam-auth
      (legacy) select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)
  -iam-auth-mount string
      the vault mount where iam auth takes place (env: IAM_AUTH_MOUNT) (default "aws")
  -infinite-auth
      infinitely attempt to authenticate (env: INFINITE_AUTH)
  -k8s-auth
      select kubernetes vault auth as the vault authentication mechanism (env: K8S_AUTH)
  -k8s-auth-mount string
      the vault mount where k8s auth takes place (env: K8S_AUTH_MOUNT, note: will infer via k8s metadata api if left unset) (default "kubernetes")
  -k8s-token-path string
      kubernetes service account JWT token path (env: K8S_TOKEN_PATH) (default "/var/run/secrets/kubernetes.io/serviceaccount/token")
  -log-level string
      defines log levels ('trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic', '') (env: LOG_LEVEL) (default "debug")
  -log-level-field-name string
      the field name used for the level field (env: LOG_LEVEL_FIELD_NAME) (default "level")
  -log-structured
      if set, log output will be JSON else writes human-friendly format (env: LOG_STRUCTURED) (default true)
  -max-auth-duration int
      the value, in seconds, for which DAYTONA should attempt to renew a token before exiting (env: MAX_AUTH_DURATION) (default 300)
  -pki-cert string
      a full file path where the vault-issued x509 certificate will be written to (env: PKI_CERT)
  -pki-domains string
      a comma-separated list of domain names to use when requesting a certificate (env: PKI_DOMAINS)
  -pki-issuer string
      the name of the PKI CA backend to use when requesting a certificate (env: PKI_ISSUER)
  -pki-privkey string
      a full file path where the vault-issued private key will be written to (env: PKI_PRIVKEY)
  -pki-role string
      the name of the PKI role to use when requesting a certificate (env: PKI_ROLE)
  -pki-use-ca-chain
      if set, retrieve the CA chain and include it in the certificate file output (env: PKI_USE_CA_CHAIN)
  -renewal-increment int
      the value, in seconds, to which the token's ttl should be renewed (env: RENEWAL_INCREMENT) (default 43200)
  -renewal-interval int
      how often to check the token's ttl and potentially renew it (env: RENEWAL_INTERVAL) (default 300)
  -renewal-threshold int
      the threshold remaining in the vault token, in seconds, after which it should be renewed (env: RENEWAL_THRESHOLD) (default 7200)
  -secret-env
      write secrets to environment variables (env: SECRET_ENV)
  -secret-path string
      (deprecated) the full file path to store the JSON blob of the fetched secrets (env: SECRET_PATH)
  -token-path string
      a full file path where a token will be read from/written to (env: TOKEN_PATH) (default "~/.vault-token")
  -vault-auth-role string
      the name of the role used for auth. used with either auth method (env: VAULT_AUTH_ROLE, note: will infer to k8s sa account name if left blank)
  -workers int
      how many workers to run to read secrets in parallel (env: WORKERS) (Max: 5) (default 1)
```

#### Deployment

DAYTONA is not deployed to any public image registry as we'd like to assume you're comfortable with deploying this somewhere that you trust.

Building a Docker image:

```shell
make image
```

Use the `REGISTRY` environment variable to define where you'd like the image to be pushed:

```shell
REGISTRY=gcr.io/supa-fast-c432 make push-image
```

Or, you can simply deploy the binary. It can be built via:

```shell
make build
```

# License

Copyright 2019-present, Cruise LLC

Licensed under the [Apache License Version 2.0](LICENSE) (the "License");
you may not use this project except in compliance with the License.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Contributions

Contributions are welcome! Please see the agreement for contributions in
[CONTRIBUTING.md](CONTRIBUTING.md).

Commits must be made with a Sign-off (`git commit -s`) certifying that you
agree to the provisions in [CONTRIBUTING.md](CONTRIBUTING.md).
