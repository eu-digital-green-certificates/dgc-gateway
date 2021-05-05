<h1 align="center">
    EU Digital Green Certificates Gateway
</h1>

<p align="center">
  <a href="https://github.com/eu-digital-green-certificates/dgc-gateway/actions/workflows/ci-main.yml" title="ci-main.yml"><img src="https://github.com/eu-digital-green-certificates/dgc-gateway/actions/workflows/ci-main.yml/badge.svg"></a>
      <a href="https://sonarcloud.io/dashboard?id=eu-digital-green-certificates_dgc-gateway" title="Quality Gate Status"><img src="https://sonarcloud.io/api/project_badges/measure?project=eu-digital-green-certificates_dgc-gateway&metric=alert_status"></a>
  <a href="/../../commits/" title="Last Commit"><img src="https://img.shields.io/github/last-commit/eu-digital-green-certificates/dgc-gateway?style=flat"></a>
  <a href="/../../issues" title="Open Issues"><img src="https://img.shields.io/github/issues/eu-digital-green-certificates/dgc-gateway?style=flat"></a>
  <a href="./LICENSE" title="License"><img src="https://img.shields.io/badge/License-Apache%202.0-green.svg?style=flat"></a>
</p>

<p align="center">
  <a href="#about">About</a> •
  <a href="#development">Development</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#support-and-feedback">Support</a> •
  <a href="#how-to-contribute">Contribute</a> •
  <a href="#contributors">Contributors</a> •
  <a href="#licensing">Licensing</a>
</p>

## About

This repository contains the source code of the Digital Green Certificates Gateway (DGCG).

DGCG is used to share validation and verification information across all national backend servers. By using DGCG,
backend-to-backend integration is facilitated, and countries can onboard incrementally, while the national backends
retain flexibility and can control data processing of their users.

## Development

### Prerequisites

- OpenJDK 11 (with installed ```keytool``` CLI)
- Maven

#### Additional Tools for starting Gateway locally

- OpenSSL (with installed CLI)
- DGC-CLI (https://github.com/eu-digital-green-certificates/dgc-cli)

### Build

Whether you cloned or downloaded the 'zipped' sources you will either find the sources in the chosen checkout-directory
or get a zip file with the source code, which you can expand to a folder of your choice.

In either case open a terminal pointing to the directory you put the sources in. The local build process is described
afterwards depending on the way you choose.

#### Maven based build for Tomcat WAR-File

```
mvn clean install
```

#### Maven based build for Docker Image

```
mvn clean install -P docker
docker-compose build
```

### Start Local

In order to start the gateway on your local computer you have to follow these steps:

* Create TrustAnchor
* Create Database
* Start Gateway
* Insert Trusted Parties

#### Create TrustAnchor

The TrustAnchor is used to sign TrustedParty entries in the DB. To validate these signatures the gateway needs to public
key of the TrustAnchor.

To create a TrustAnchor you can execute the following OpenSSL command:

```
openssl req -x509 -newkey rsa:4096 -keyout key_ta.pem -out cert_ta.pem -days 365 -nodes
```

afterwards the PublicKey has to be exported in a Java KeyStore.

```
keytool -importcert -alias dgcg_trust_anchor -file cert_ta.pem -keystore ta.jks -storepass dgcg-p4ssw0rd
```

Put the created ta.jks file in the "certs" directory of dgc-gateway. (Create directory if not already existing)

#### Create Database

DGC Gateway needs a database to persist data. For local deployment a MySQL is recommended. A MySQL DB will be started
when docker-compose file is started, so no additional tasks are required.

#### Start Gateway

To start the Gateway just start the docker-compose file. Please assure that the project was build for Docker build
before.

```
docker-compose up --build
```

#### Common issues

`ERROR: for dgc-gateway_dgc-gateway_1  Cannot create container for service dgc-gateway`

This error occurs in Docker-for-Windows if Docker does not have access to the gateway folder. In Docker-for-Windows, 
go to `Settings > Resources > File Sharing` and add the root directory of the repository, then restart Docker-for-Windows.

#### Insert Trusted Parties

The data structure in the database should be now be created by DGC Gateway. In order to access the DGC Gateway is is
required to onboard some certificates. You will need AUTHENTICATION, UPLOAD and CSCA certificates.

The certificates can be created with OpenSSL:

```
openssl req -x509 -newkey rsa:4096 -keyout key_auth.pem -out cert_auth.pem -days 365 -nodes
openssl req -x509 -newkey rsa:4096 -keyout key_csca.pem -out cert_csca.pem -days 365 -nodes 
openssl req -x509 -newkey rsa:4096 -keyout key_upload.pem -out cert_upload.pem -days 365 -nodes
```

To sign them with TrustAnchor you can use DGC-CLI

```
dgc ta sign -c cert_ta.pem -k key_ta.pem -i cert_auth.pem
```

Afterwards you can create a new entry in the trusted_parties table and fill all field with the data from command above.

#### Send requests

DGC Gateway does not do any mTLS termination. To simulate the LoadBalancer on your local deployment you have to send
HTTP requests to the gateway and set two HTTP-Headers:

X-SSL-Client-SHA256: Containing the SHA-256 Hash of the AUTHENTICATION certificate (thumbprint from dgc ta command
output)
X-SSL-Client-DN: Containing the Distinguish Name (Subject) of the AUTHENTICATION certificate. (Must only contain Country
Property, e.g. C=EU)

## Documentation

You can find the latest OpenAPI Spec here: https://eu-digital-green-certificates.github.io/dgc-gateway/

See [./docs/software-design-dgc-gateway.md](./docs/software-design-dgc-gateway.md).

## Support and feedback

The following channels are available for discussions, feedback, and support requests:

| Type                     | Channel                                                |
| ------------------------ | ------------------------------------------------------ |
| **Gateway issues**    | <a href="/../../issues" title="Open Issues"><img src="https://img.shields.io/github/issues/eu-digital-green-certificates/dgc-gateway?style=flat"></a>  |
| **Other requests**    | <a href="mailto:opensource@telekom.de" title="Email DGC Team"><img src="https://img.shields.io/badge/email-DGC%20team-green?logo=mail.ru&style=flat-square&logoColor=white"></a>   |

## How to contribute  

Contribution and feedback is encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](./CONTRIBUTING.md). By participating in this project, you agree to abide by its [Code of Conduct](./CODE_OF_CONDUCT.md) at all times.

## Contributors  

Our commitment to open source means that we are enabling -in fact encouraging- all interested parties to contribute and become part of its developer community.

## Licensing

Copyright (C) 2021 T-Systems International GmbH and all other contributors

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License.
