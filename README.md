<h1 align="center">
   EU Digital COVID Certificate Gateway
</h1>

<p align="center">
  <a href="https://github.com/eu-digital-green-certificates/dgc-gateway/actions/workflows/ci-main.yml" title="ci-main.yml">
    <img src="https://github.com/eu-digital-green-certificates/dgc-gateway/actions/workflows/ci-main.yml/badge.svg">
  </a>
  <a href="https://sonarcloud.io/dashboard?id=eu-digital-green-certificates_dgc-gateway" title="Quality Gate Status">
    <img src="https://sonarcloud.io/api/project_badges/measure?project=eu-digital-green-certificates_dgc-gateway&metric=alert_status">
  </a>
  <a href="https://github.com/eu-digital-green-certificates/dgc-gateway/actions/workflows/codeql.yml" title="CodeQL">
  <img src="https://github.com/eu-digital-green-certificates/dgc-gateway/actions/workflows/codeql.yml/badge.svg">
  </a>
  <a href="/../../commits/" title="Last Commit">
    <img src="https://img.shields.io/github/last-commit/eu-digital-green-certificates/dgc-gateway?style=flat">
  </a>
  <a href="/../../issues" title="Open Issues">
    <img src="https://img.shields.io/github/issues/eu-digital-green-certificates/dgc-gateway?style=flat">
  </a>
  <a href="./LICENSE" title="License">
    <img src="https://img.shields.io/badge/License-Apache%202.0-green.svg?style=flat">
  </a>
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

This repository contains the source code of the EU Digital COVID Certificate Gateway (DGCG).

DGCG is used to share validation and verification information across all national backend servers. By using DGCG,
backend-to-backend integration is facilitated, and countries can onboard incrementally, while the national backends
retain flexibility and can control data processing of their users.

## Development
Please be aware that the provided configuration files contain passwords that do not conform to any reasonable password policies, hence under no circumstances should be applied to productive or even broader test environments.
Passwords used in productive scenarios should be provided only at runtime and stored in safe place, with restricted and logged access.  
### Prerequisites

- OpenJDK 11 (with installed ```keytool``` CLI)
- Maven
- Authenticate to [Github Packages](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry)

#### Authenticating to GitHub Packages

As some of the required libraries (and/or versions are pinned/available only from GitHub Packages) You need to authenticate
to [GitHub Packages](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry)
The following steps need to be followed

- Create [PAT](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token) with scopes:
  - `read:packages` for downloading packages

##### GitHub Maven

- Copy/Augment `~/.m2/settings.xml` with the contents of `settings.xml` present in this repository
  - Replace `${app.packages.username}` with your github username
  - Replace `${app.packages.password}` with the generated PAT

##### GitHub Docker Registry

- Run `docker login docker.pkg.github.com/eu-digital-green-certificates` before running further docker commands.
  - Use your GitHub username as username
  - Use the generated PAT as password

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

**Attention: This Repository contains simple passwords as placeholder. Please be aware that these passwords should not
be used for production deployments of the gateway!**

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

Put the created ta.jks file in the "certs" directory of dgc-gateway. If you are using the Docker image then this folder must
be in the root directory of your local workspace (on the same level as this readme file). Create directory it does not already exist.

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

The data structure in the database should be now be created by DGC Gateway. In order to access the DGC Gateway it is
required to onboard some certificates. You will need AUTHENTICATION, UPLOAD and CSCA certificates.

The certificates can be created with OpenSSL:

```
openssl req -x509 -newkey rsa:4096 -keyout key_auth.pem -out cert_auth.pem -days 365 -nodes
openssl req -x509 -newkey rsa:4096 -keyout key_csca.pem -out cert_csca.pem -days 365 -nodes 
openssl req -x509 -newkey rsa:4096 -keyout key_upload.pem -out cert_upload.pem -days 365 -nodes
```

To sign them with TrustAnchor you can use DGC-CLI:

```
dgc ta sign -c cert_ta.pem -k key_ta.pem -i cert_auth.pem
dgc ta sign -c cert_ta.pem -k key_ta.pem -i cert_csca.pem
dgc ta sign -c cert_ta.pem -k key_ta.pem -i cert_upload.pem
```

Afterwards you can create a new entry in the `trusted_parties` table and fill all of the fields with the data produced by the above commands.

##### Inserting Trusted Parties into the Database

Log on to the mysql container (using the docker commands or opening a shell with the docker UI) and open mysql cli like this:

```
mysql --user=root --password=admin dgc
```

To show the available tables:

```
 select * from INFORMATION_SCHEMA.tables where table_schema='dgc';
```

We're interested in the table `trusted_party`; you can see the structure of it by using this command:

```
describe trusted_party;
```

To insert your certificates you can do this (replacing this with your own information from the `dgc` command):

```
INSERT INTO trusted_party (created_at, country, thumbprint, raw_data, signature, certificate_type)
SELECT
	NOW() as created_at,
	'NL' as country,
	'{Certificate_Thumbprint}' as thumbprint,
	'{Certificate_Raw_Data}' as raw_data,
	'{TrustAnchor_Signature}' as signature,
	'{AUTHENTICATION|UPLOAD|CSCA}' as certificate_type;
```

Here is a set of example queries including all of the data:

```
-- Authentication certificate
insert into trusted_party (created_at, country, thumbprint, raw_data, signature, certificate_type)
select
	now() as created_at,
	'NL' as country,
	'397da9eb17467a2b3b83704ab6490a540bef43e84f06a6bd885e6621572da401' as thumbprint,
	'MIIFrzCCA5egAwIBAgIUPg0bGwARBnhfTWmOTpOOdYMKESMwDQYJKoZIhvcNAQELBQAwZzELMAkGA1UEBhMCTkwxDDAKBgNVBAgMA1RMUzEMMAoGA1UEBwwDVExTMQwwCgYDVQQKDANUTFMxDDAKBgNVBAsMA1RMUzEMMAoGA1UEAwwDVExTMRIwEAYJKoZIhvcNAQkBFgNUTFMwHhcNMjEwNTA1MTAxOTMwWhcNMjIwNTA1MTAxOTMwWjBnMQswCQYDVQQGEwJOTDEMMAoGA1UECAwDVExTMQwwCgYDVQQHDANUTFMxDDAKBgNVBAoMA1RMUzEMMAoGA1UECwwDVExTMQwwCgYDVQQDDANUTFMxEjAQBgkqhkiG9w0BCQEWA1RMUzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALiYJTlNwVftS7k794t/Zog54HQGTPrjreDa4c4eQT3fzjjFF7QnyLn1yERggBX3v0pVP8skTxTMbYc9uLFNYNcpMT6H6eNQDKLmyGIoh8Lq4HQ6vLUGse1IjOreJNtCyFB5z4hFeY/QmJykBza9HE+Pfw9O/otOqO2Jpupk1r+dxlL0+kugRFB+vepmeNMocbFT6mPzQdzToNdMMvuNKNxP/2NeDTzpxVdDQTHvqCK6bQuVcBj6NkLMTkdx2h0iPy7Xwoq8t5Wui/AF4c8lkdIu9/OlLMSCGTX6LaB9zxXEQVCZKml6TZ9snNe9T6OTEuFAGjKr+rpgSL3zNxfo0FurO/Rs+H1w7424yKGPL4WOBtXR9EHZz1/l8YR9tXCGlqarsFjzmZIsUvOFdRFCVAxzYsWRUdWn5wZ9YpG5wbUjzImnLm0nCBdyrnEHBhWHPXS6uXHueEuKJb5gg0Y6+owD9tMYZ7y9tgH6JaYHMYbHKDoOa0cpbUQVjhGA2ce7axIQMo/mSvd5CxXapH5N0Zope7yDjUiyNdRsHJj24r/LpxXBm7eMtIWAlsaXBL1OYF3TJXnVFXWacxaZqKam1orJrmWwyWmd2qwq/ycvs2cDjSipMNKC8WYPI11jnjLC1YcaBEVPRr2BG2mDMFZu7HGxGPIRyWC/IJn7D1LEzywVAgMBAAGjUzBRMB0GA1UdDgQWBBQw3Wsw2XD3R0MgcPpnXSvdnAJedDAfBgNVHSMEGDAWgBQw3Wsw2XD3R0MgcPpnXSvdnAJedDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCNfqF1DmFLOCOtNF/I4ZMbS4gZymEe6v3dUw9Z4eGcQWGgz19bmpeh8l21PNU+c+KgemQAoa7XMnrfySpjnVDqJ7+k6Dba4KY8ImwIDkY/RYXQxgqXGudxMiPUul0CGpjzvo385Z5VppNWu3ZgRcTcAUCe+42mWpfmvQGEJailRSoIY5K7GceaP62dRgkAmVnq8tP/EtLvnrAlAo1xk00sVLJUnxpBl/J5yOua1qM10ROo/6Md3IB820L7jOUki0rLmH2FzbdEu15PPwnxtHyjgDIr+JbY1BYnCihHI8635HBS1pv+hAj0M0cBY+ChuD5V5yfCCM+QxZM4q4HNd9Fb3hIyfod5KHKTzFxYkpG54KKYUgyPHdEMuj3RFzcIYcYlAdyfc1Q0Ms0YyqeV6Xu0HjibeV16wfZ/+0SLK6WkzMOutLL7L73xVAo1AnIkXUXjQnDOjGusttH7RbMC6BdiC/SevQQuCsFO1b0dx1OQxehNe0wiaFj63ZPXjUFz5QhCPqhZJKjEXmK55RLBUpkYOGNdcS96t+8vI+HucZAqR+2Vu00K6od3cAqjTPV37PxQQY47BnNqIjOzWqvykZNLovQ28iccZWn3R1OkWXbN44+ehGoB2ELFrdu5B3GoWXEP0RSe7+Jo2unoq77rIq4qVoKsyG7+6YDjDy6qV5HdJQ==' as raw_data,
	'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' as signature,
	'AUTHENTICATION' as certificate_type;

-- Upload certificate
insert into trusted_party (created_at, country, thumbprint, raw_data, signature, certificate_type)
select
	now() as created_at,
	'NL' as country,
	'7a58cc85a1bcfecb1bc69822cc2a72dfb4fbc9fe23d588fa9b0660b929d368f9' as thumbprint,
	'MIIF0zCCA7ugAwIBAgIUZiCTld5e+Bhk5ott4lejMfphwAMwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCTkwxDzANBgNVBAgMBlVQTE9BRDEPMA0GA1UEBwwGVVBMT0FEMQ8wDQYDVQQKDAZVUExPQUQxDzANBgNVBAsMBlVQTE9BRDEPMA0GA1UEAwwGVVBMT0FEMRUwEwYJKoZIhvcNAQkBFgZVUExPQUQwHhcNMjEwNTA1MTAyNTI1WhcNMjIwNTA1MTAyNTI1WjB5MQswCQYDVQQGEwJOTDEPMA0GA1UECAwGVVBMT0FEMQ8wDQYDVQQHDAZVUExPQUQxDzANBgNVBAoMBlVQTE9BRDEPMA0GA1UECwwGVVBMT0FEMQ8wDQYDVQQDDAZVUExPQUQxFTATBgkqhkiG9w0BCQEWBlVQTE9BRDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMCrQqfrlprHDAGsaa7eVfBLxBmJ94+N+rNZ51Jlq3zkYV0nNzPpzac3TgNu7Vz6LeWdKBf07ozEQRNM6ojFBT+1Af+3jbT43sqs+qnRJLaD0vO0U0JPtBjk1OGkRaSJFwRId6XQWm0qjeE9Z5F8XjmA+2pSKDja37G7u4zOxnQ7qC1tI3Vs4rahonOk7npXi02o//v1VVaBlKiF4HTZhFaAIGWtoz9SDtLxPJiTGvwx/5NTJlWia1Y0t0Br+kCfuLsAnM20HnwY3CO2RPhkSC2eEDSZ6jFYaah1ggfmSanlHTlwkGzyx6P7aNlcOYCiqERYG61yjVHC5Rd8+aQeGcmF1kXF91Fz0w+LWMZ1FaRQ32bHYGv1M62BZrH58cor9eVc98iKGmlKh8VJ6Qr1bNlijD5BONfFQeKgwFGIdMJrZtbYFMDra+7RmIA+SMf3SaQsYzngBDHiQSjyTHjO3dg7PM5ZDYI79onM9SF3W3Ogj8CM+SgE67kxbvMS92zLbPB7UwJjd4j4JMDM8Z4yf9Kq/cE0mcuZVUs+9ow8LUmPGvQmRZvIpAg3m+XRnMOziUhukx3vI6NzbiqTd4rIR5RBIlgNnTxCwlb5L+6Td/C26HjpKzTTkico2vd8ux61KeG9M7nlsOU+T+w4Ff2Tcpc8eEJZkV0/hIjTIVj1hvmjAgMBAAGjUzBRMB0GA1UdDgQWBBQ9eygTuQWztj0o0b4OCqQNtqPoqzAfBgNVHSMEGDAWgBQ9eygTuQWztj0o0b4OCqQNtqPoqzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCZ/48PbHIFUDbNdqGvcw/UgT2ZlF7GhrWB667iP2XEi8m58eYvYLASV0ujhfVEhS3/Sr41fW2hApv47xU2uqkvJSMZ0bNePQv5kakVUaF/a3CtPXoYo29vXBCX1DebNoSjHMBjZRe4f6TZEY7sD9Za9Nvcvpy6Q6ly1tSyqYU/0V2DwmvDKndaF2ejNBwuc9o/FcYWPi3bGjPexbYhqjqp8ZrMbITkKibP6CXFFikAx0xVT8cHU2yBhAjclnVJMfYnzECYmO3Cpuf7r5HK204nWBkG5mnoVb6D7qtjiLImDJGMTGi2RY9AlyD968QNbh7/PcCWptVZdUOrAOOd/yYo+YucVZNcxgSNfkVjE7YCDYQr4Lf0dV47MNPXe/QOFB6fKmueQtRMl2Hn1ht+cojoG3i+qiSEwJKh2hSNGimZBT6AEd93/XA3hmsWA7UcX/YV5HZdPpc9T38vE08f4bB/JBq2yJ58LOpDpUMaVA6wkzmwXDRHBpKeMEDz2JgDZJN+Ud3mo16z7mFEgIqYNGVJvvfeRTrLOoyy+39Ge9amzeArcEqjbQ75qb/cHwJAyElKPQNh6Iet8g5o33yxDsP5LTju3s6ssU4F/CXlZ35QectNvLTx0ewfjxnDFCiAs0zy0I4jf8tb/Obx+awXrRblgGGcHjIcFUk5E3gVY5CDjg==' as raw_data,
	'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' as signature,
	'UPLOAD' as certificate_type;

-- CSCA certificate
insert into trusted_party (created_at, country, thumbprint, raw_data, signature, certificate_type)
select
	now() as created_at,
	'NL' as country,
	'a5d441bfa7fdbc2b64b73fb1d78e801bc131d670f6e97218a1625098b3ced707' as thumbprint,
	'MIIFuzCCA6OgAwIBAgIURm8BBiv9BHHG479oKAOOg0kGOvgwDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCTkwxDTALBgNVBAgMBENTQ0ExDTALBgNVBAcMBENTQ0ExDTALBgNVBAoMBENTQ0ExDTALBgNVBAsMBENTQ0ExDTALBgNVBAMMBENTQ0ExEzARBgkqhkiG9w0BCQEWBENTQ0EwHhcNMjEwNTA1MTAxOTU1WhcNMjIwNTA1MTAxOTU1WjBtMQswCQYDVQQGEwJOTDENMAsGA1UECAwEQ1NDQTENMAsGA1UEBwwEQ1NDQTENMAsGA1UECgwEQ1NDQTENMAsGA1UECwwEQ1NDQTENMAsGA1UEAwwEQ1NDQTETMBEGCSqGSIb3DQEJARYEQ1NDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKXXPXyaDm2GQ9Cs5+MM7jvtOQODwRI4s5kIB2iyG4gOfADEOVe6DYNRm1lvqAdTCrgUw9/quGKPEpfP/4kbit8auU1MY2haicOBYDHcJDAa5UHXCOhEvCF45diehCIy582kNP0fxEQJM7KBe+XsJDyH9joA50V3JKXhih6Nx4iqAq/JyNg29E25FUC3Ml2SPZmE6g/IlidT8+B8NDPVHgGjH5a9+vOjCAUVoIcON+Ez8H/Yop87AfMGhjtSeuJCJ6F4lVfnsSQ4wbAEHKR7YKyyPAm5NAiWQ22FyM4UFS+vNijmWfLcS4uyKfxVk8gBuBOqszZrqmL5VQhFiRwz9MNtj1rUb4ZOFm2laecDXj15oVUTgw7mNLX8MB4jCyjrxUeOQ9XrVdmWQCUm3Sdf9eBwX60J0tkiuPJauaIV115r5CzXxQ3D8y+6B9mDS+7lciIaX/SzFMqI79BwJ1Klc3A8MNt0lIAYhDPSh1BGs7JAGzNbF88Sh1RWF4yJhdfIKl+e5uKXgtlzK6MqbWpr8T0lsV/DccMei9TgXiSwbPQ8DT83WRvDsPyYTWJmfCtCjTE8hWMXiStmpQaYf6fsPMdNW/8l03kpmYwmHL3ToU9e5N6cEyuUGNMjIZB8zMwta4ZdUinG62rvgEK/e6+adE4UG9hfWvs/CcXbYwt7UGK/AgMBAAGjUzBRMB0GA1UdDgQWBBSsY6WtCh6zKpcWm9jLr8pSlwxSfDAfBgNVHSMEGDAWgBSsY6WtCh6zKpcWm9jLr8pSlwxSfDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQBCvDxMoziwQueLaBwDIe+UnXahaoNdw7Rw6wp4fMqccRs6mCRYYX5h2W9ukTX71BcuSyPGUdewHKndvG33odp9Vwm3a/63LiBJqk0+TGfbj5brD8DN5E0+EL3PNxEBGe81Nz2UctAr1rjHuKfCeHR+xzZZTKnDEg1lzs6VV13K9iN4Q9f9HeCvSqHNcbQEweFKZfk2tEJHjjlBwDwYWWfFraVA4FykzYrmZPBtMqrG+UWQJI6B/FjkC3urmotAP3MLjTwhhtIayzkCNpmnkvvbrY/pVnWPEzEptSqdWp3w+jTCEzd0VJeJlH9kOYxi0Mg5KaCONxCQrwI+iKoQnEwjF9cvYo+wVmslYiHMgT+0Ik4jopIiVCinKCeGjt2Ol7eGETfpg1mzjMta4+Abq1N9U36iD3qi/PhSSc6ApCr7ddfLxPLEeDu4Pt/BxsGyPNWPI7gtXLom2+gvbbMRDGpBqDHB/crE4OAAWe0DIrhaOFmSNH+yy8gEkSXfUn1FupVVeOAAOVLpRPQQaC6SxdNXufsO/mzMco5DQUovhrj1HyNM261tpupJgoR0JC8fNIAYAmdy/57ibSn/i48J+PcsaCskzzcYDA18XThImvodGlAWlFa6qhCEhJ/cbrFp75e6pU3CrP6/gf+ssAmbDWfLbNOAI1U4GY1q6+MxhH+bdA==' as raw_data,
	'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' as signature,
	'CSCA' as certificate_type;
```

#### Testing that everything works

You can test that everything works quickly by using this curl:

```
curl -X GET http://localhost:8080/trustList -H "accept: application/json" -H "X-SSL-Client-SHA256: 397da9eb17467a2b3b83704ab6490a540bef43e84f06a6bd885e6621572da401" -H "X-SSL-Client-DN: C=NL"
```

* Replace the example SHA with that of your own test certificate in the `X-SSL-Client-SHA256` header
* Replace the example country with your own country in the `X-SSL-Client-DN` header (i.e. US, CN, ZA) 

That command will return something looking like this (but with large base64 strings)

```
[
  {
    "kid":"OX2p6xdGeis=",
    "timestamp":"2021-05-05T12:54:49Z",
    "country":"NL",
    "certificateType":"AUTHENTICATION",
    "thumbprint":"397da9eb17467a2b3b83704ab6490a540bef43e84f06a6bd885e6621572da401",
    "signature":"<snip>",
    "rawData":"<snip>"
  },
  {
    "kid":"eljMhaG8/ss=",
    "timestamp":"2021-05-05T12:57:26Z",
    "country":"NL",
    "certificateType":"UPLOAD",
    "thumbprint":"7a58cc85a1bcfecb1bc69822cc2a72dfb4fbc9fe23d588fa9b0660b929d368f9",
    "signature":"<snip>",
    "rawData":"<snip>"
  },
  {
    "kid":"pdRBv6f9vCs=",
    "timestamp":"2021-05-05T12:57:36Z",
    "country":"NL",
    "certificateType":"CSCA",
    "thumbprint":"a5d441bfa7fdbc2b64b73fb1d78e801bc131d670f6e97218a1625098b3ced707",
    "signature":"<snip>",
    "rawData":"<snip>"
  }
]
```

NOTE: the url uses mixed cases; it's `trustList` not `trustlist`!

If something goes wrong, the best place to look is in the logging.

Docker users can read the logs by copying them to their machine; use `docker ps` to get the ID of the running containers
and `docker cp [CONTAINER_ID]:/logs/dgcg.log .` to copy the log file to the current directory.

#### Send requests

DGC Gateway does not do any mTLS termination. To simulate the LoadBalancer on your local deployment you have to send
HTTP requests to the gateway and set two HTTP-Headers:

X-SSL-Client-SHA256: Containing the SHA-256 Hash of the AUTHENTICATION certificate (thumbprint from dgc ta command
output)
X-SSL-Client-DN: Containing the Distinguish Name (Subject) of the AUTHENTICATION certificate. (Must only contain Country
Property, e.g. C=EU)

#### Coverting the certificate/private key into PKCS12

Windows users may wish to convert their certificate/private keys into a PKCS12 package so that it can be imported into the 
machine's certificate store. Thankfully that is pretty simple using openssl.

For example to convert the test authentication certificate created earlier:

```
     openssl pkcs12 -export -out auth.pfx -inkey key_auth.pem -in cert_auth.pem
```

## Documentation

### OpenAPI Spec

The latest OpenAPI specification can always be found here: https://eu-digital-green-certificates.github.io/dgc-gateway/

It is also possible to access OpenAPI when DGC Gateway is deployed on your local computer when Spring-Profile "dev" or "
local" is enabled. In order to set authentication headers for authentication without a mTLS terminating LoadBalancer at
least the profile "local"
should be enabled. Then both headers can be set in Swagger UI.

http://localhost:8090/swagger-ui/index.html

### Other Documentation

* [Software Design](docs/software-design-dgc-gateway.md)
* [Onboarding Document](https://github.com/eu-digital-green-certificates/dgc-participating-countries/blob/main/gateway/OnboardingChecklist.md)

## Support and feedback

The following channels are available for discussions, feedback, and support requests:

| Type                     | Channel                                                |
| ------------------------ | ------------------------------------------------------ |
| **Gateway issues**    | <a href="/../../issues" title="Open Issues"><img src="https://img.shields.io/github/issues/eu-digital-green-certificates/dgc-gateway?style=flat"></a>  |
| **Other requests**    | <a href="mailto:opensource@telekom.de" title="Email DGC Team"><img src="https://img.shields.io/badge/email-DGC%20team-green?logo=mail.ru&style=flat-square&logoColor=white"></a>   |

## How to contribute  

Contribution and feedback is encouraged and always welcome. For more information about how to contribute, the project structure, 
as well as additional contribution information, see our [Contribution Guidelines](./CONTRIBUTING.md). By participating in this 
project, you agree to abide by its [Code of Conduct](./CODE_OF_CONDUCT.md) at all times.

## Contributors  

Our commitment to open source means that we are enabling -in fact encouraging- all interested parties to contribute and become part of its developer community.

## Licensing

Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with
the License.

You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" 
BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the [LICENSE](./LICENSE) for the specific 
language governing permissions and limitations under the License.
