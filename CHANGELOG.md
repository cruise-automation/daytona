## 1.1.5 - Unreleased

- Update to go 1.16
- Address a potential deadlock in the parallel secret reader
- Secrets can be written to file paths whose parents do not exist; parents are created as needed
- Updates; golang 1.16 -> 1.16.3. Upgrade all direct dependencies

## 1.1.4 - Oct 23, 2020

- Fix panic when vault returns non-string types. string and map[string]interface{} are the only supported types at the moment.
- Attempt to locate destination definitions that don't have a matching source definition. This provides some best effort backward compatibility to pre 1.1.0 versions

## 1.1.3 - Oct 5, 2020 

- Handle rate limiting responses returned from a vault

## 1.1.2 - Sep 24, 2020

- Introduce the option to output DAYTONA log events as structured data (JSON)

## 1.1.1 - Mar 25, 2020

- Introduce a Value Key prefix that can be used for retrieving a single value from a singular secret definition
- Don't error when encountering a sub-path during a plural secret definition walk

## 1.1.0 - Mar 19, 2020

- Introduces arbitrary suffix identifiers for Secret Definitions.

## 1.0.2 - Oct 16, 2019

- Parallel secret fetching
- Naive (no x509/pkix required) issuance of certs/keys from PKI backend
- Minor documentation updates and bug fixes

## 1.0.1 - Jun 20, 2019

- Applied stricter linting
- Tidy/update vendor
- Minor documentation updates

## 1.0.0 - May 7, 2019

- Initial release of DAYTONA, a HashiCorp Vault client, but for servers and containers.