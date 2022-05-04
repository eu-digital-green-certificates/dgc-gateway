EU Digital Covid Certificates Signer Certificates Archive

The archive is published under the license described in License.txt - Please be aware of this license when distributing
this archive or contents of it.


Content:

    1. Intention
    2. Structure of archive
    3. How to verify integrity of DCC
    4. How to verify integrity of this archive

1. Intention
    The content of this archive can be used to verify that a Digital Covid Certificate (DCC) was issued by an authorized
    issuer. Note that in order to lawfully process the personal data contained in a DCC, verifiers need a legal basis pursuant
    to Article 6 of Regulation (EU) 2016/679 (GDPR). 

2. Structure of archive
    This archive contains two different certificate types: Digital Signer Certificate (DSC) and Country Signing Certificate
    Authority (CSCA). The archive is structured by certificate type (DSC or CSCA), domain (currently just DCC) and the
    2-digit country code.
    The certificates are encoded as PKCS#8 saved in pem files named by there certificate SHA-256 thumbprint.

    CSCA
      ∟ DCC
        ∟ CC
          ∟ 6d3644ee122d1263267c6f42974c42acc3ca1a08675264fe34360239b5605e0e.pem
    DSC
      ∟ DCC
        ∟ CC
          ∟ 6493815d2ecfdbab6507e541a5f53e68b03d057b45e16d39b35b91ee61f78ab0.pem

3. How to verify integrity of DCC
    A. Extract Signature from DCC
    B. Get KID from DCC, Convert Base64 string to hex, search for DSC file starting with the resulting hex string
    C. Verify that DCC was signed by the DSC
    D. Verify that the matching DSC was issued by one of the CSCA

4. How to verify integrity of this archive
    This archive and all of its contents are signed by a certificate of the European Commission.
    The signature file will be seperatly distributed. You can find it on the same download page as this archive ([URL]).
    The signature file contains a base64 encoded CMS-Message with detached payload (PKCS#7).

    There are two options to verify the integrity of the archive:

    A: DGC-CLI (recommended, needs DGC-CLI to be installed)
        - Install DGC-CLI: https://github.com/eu-digital-green-certificates/dgc-cli#installation
        - Verify integrity
            dgc signing validate-file -i dcc_database.zip.sig.txt -p dcc_database.zip

        The command will output only the verification result and the subject and thumbprint of the signer certificate.
        The thumbprint should be checked against the published signer certificate.

    B: OpenSSL (Needs OpenSSL CLI to be installed)
        - Convert signature file from base64 encoded to plain DER file
            openssl base64 -a -A -d -in dcc_database.zip.sig.txt -out dcc_database.zip.sig.der
        - Verify integrity
            openssl cms -verify -in dcc_database.zip.sig.der -inform DER -content dcc_database.zip -binary -CAfile eu_signer.pem

        The output of the verify command contains the whole binary data of the zip file.
        At the end of the output you should find: "Verification successful"

