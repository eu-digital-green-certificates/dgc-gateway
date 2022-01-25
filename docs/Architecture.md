# Terminology



|Term     |       Description       | 
|---------|--------------------------|
|DCC |   Digital Covid Certificate.|
|DDCC|Digital Documentation Covid Certificate.|
|DCC Gateway (DCCG) |REST web-application for exchange of document signer certificates, dcc value sets, dcc business rules and revocation lists for dcc verification purposes between the national backends of connected states.|
|DDCC Gateway (DDCCG)|Digital Documentation Covid Certificate Gateway is an extended version of the DCCG. It is enhanced functionality allowing for interoperability between multiple gateways and in support of the DDCC specification.|
|Member State| Any country which is connected to DDCC gateway. Member States should provide at least one National Backend for connecting to DDCCG.
|CSCA |Country Signing Certificate Authority. This is a signing certificate which is used to issue DSC. This certificate is stored securely and used via an air-gap to issue DSC.|
|DSC| Document Signer Certificate.  The DSC is the certificate used to digitally sign the vaccination credential. |
|NB|National backend. The Member State national backend system for managing the local part of information. The implementation of NB is not in the scope of this document. A national backend can be also understood as a trusted party onboarded in the gateway (can be a script, a proxy or a web server as well).|
|NB<sub>TLS</sub>|The TLS client authentication certificate of a national backend, used to establish the mutual TLS connection from the NB to the DDCCG.|
|NB<sub>UP</sub>|The certificate that a national backend uses to sign data packages that are uploaded to the DDCCG.|
|DDCCG<sub>TA</sub>|The Trust Anchor certificate of the DDCCG formerly known as DCCGTA or DGCGTA. The corresponding private key is used to sign the list of all CSCA certificates offline.|
|CMS| Cryptographic Message Syntax. According [RFC5652](https://datatracker.ietf.org/doc/html/rfc5652).|
|JRC|European Joint Research Centre.|
|OG|Origin Gateway.|
|[CQL](https://cql.hl7.org/)|Clinical Query Language.|

# Introduction
This architectural specification provides the means to establish a federated trust network for use with the WHO Digital Documentation of Covid Certificates (DDCC) guidance documents and specifications.   An assumption of this document is that WHO Member States may establish their own independent national trust networks, participate in a regional trust network, or wish to participate in a global federated trust network, and that they wish for these trust networks to be interoperable for domestic and cross-jurisdictional use.   While specific governance and policy considerations needed in the establishment of such interoperable trust networks is out of scope of this document, the intent is that the technical design within this document would support multiple national and cross-jurisdictional policies.  

The DDCC Gateway (DDCCG) specifications in this document are designed to support the DDCC specification, which acts as bridging/umbrella specification for various digital covid certificates (e.g. EU’s DCC, Smart Health Cards, DIVOC, and ICAO).  This specification builds of the [EU Digital Covid Certificate Gateway](https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v2_en.pdf) by extending it in several important ways:
- allowing for federation and peer exchange of information between gateways;
- supporting access to metadata content (e.g. value sets/codings, business rules) with explicit adherence to the HL7 FHIR specification;
- providing an explicit means for revocation of digital covid certificates; and
- allowing for (optional) support of online verification and validation workflows.

Within the current DCC system the centralized gateway plays the key role of establishing  trust between all of the connected Member States. The gateway operators follow a well documented process to establish the identity and onboard the trust anchor of each Member State. The DDCCG builds upon this system to enable the creation of trust gateways by other organizations which can then form a federated network of trust gateways, supporting all of the major covid credential certificates.

# Trusted Party vs. National Backend
The current DCC Gateway design is fully focused on the trust establishment between “National Backends” in terms of a system operated/owned by a national health authority. This can be a script, a fully automated solution or a manual process, which is able to connect the gateway trustfully and be able to do the up and downloads of the content. What other concrete solutions are behind is not more scope of the gateway itself. Within the DDCC scope, it’s not more precise to speak about “National Backend”, because there can be other parties which can be connected with their publishing system to a gateway in the network. Therefore the term “national backend” should be understood within this scope more as “Trusted Party” in terms of an attendee which gots access to a trusted gateway. The trusted gateway or the federator acts then as well as “Trusted Party” to other gateways.



