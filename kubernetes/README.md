# Installation

The gateway kubernetes ymls are currently aligned to the [Reference Setup](https://github.com/WorldHealthOrganization/ddcc-trusted-party-reference-implementation). This means for installing the yml  must be currently a hashi corp vault in place as described in the manual of the reference setup. 

After setting up the basic infrastructure, the secrets must be defined for: 

- [MTLS](https://medium.com/@niral22/2-way-ssl-with-spring-boot-microservices-2c97c974e83)
- Truststore
- Trustanchor
- Federation

Each secret contains a keystore, a password and optionally a private key password/alias. 

## Creating the Keystores

Download the [keystore explorer tool](https://keystore-explorer.org) or use the standard [keytool] for the console. Create a keystore (JKS) for mtls, truststore and trustanchor. Import into the truststore all certificates (Public Key of Client Certificate) which shall pass the MTLS security check. Within the MTLS keystore do you need to add an key pair + certificate which identifies the gateway to the outside world. This must be an TLS certificate issued of the DNS name of the server where the gateway is hosted. Into the trustanchor keystore is at least the certificate from the certificate operator added which signes all the trusted party entries. The federation keystore gets an key pair including the client certificate which is used to connect other gateways.

## Transforming the Keystores

The keystores must be transformed in a base64 string which must be copied to the secrets. This can be achieved by using the built-in base64 encoder/decoder of the bash or powershell engine. 

## Setup the secrets

For configuring the MTLS, create in the vault a key store for MTLS section with the following key pairs:

- SERVER_SSL_KEY_PASSWORD (PW for the Private Key)
- SERVER_SSL_KEY_ALIAS (Alias for the private Key in JKS)
- SERVER_SSL_KEY_STORE (Path for Keystore JKS)
- SERVER_SSL_KEY_STORE_PASSWORD (PW for the Key Store JKS)
- SERVER_SSL_TRUST_STORE (Path for Truststore JKS)
- SERVER_SSL_TRUST_STORE_PASSWORD (PW for the Truststore JKS)

Export this environment variables within the container (or inject it by using aliases).

Create then as well a section for trust anchor and set the keys for: 

- DGC_TRUSTANCHOR_CERTIFICATEALIAS
- DGC_TRUSTANCHOR_KEYSTOREPATH
- DGC_TRUSTANCHOR_KEYSTOREPASS

Do the same for Federation: 

- DGC_FEDERATION_KEYSTOREPASSWORD
- DGC_FEDERATION_KEYSTOREKEYPASSWORD
- DGC_FEDERATION_KEYSTOREPATH

