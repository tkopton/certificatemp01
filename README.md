# SSL/TLS Certificate Checker Management Pack

The purpose of this Management Pack is to monitor SSL and TLS certificates for endpoints that are not included out-of-the-box in VCF Operations—primarily non-VCF components, meaning practically anything that secures a service with a certificate.

This Management Pack is designed as a modern and superior alternative to my old approach using Telegraf and scripts, as described in my blog: https://thomas-kopton.de/vblog/?p=538.

#### Collected Properties

* `protocol_family`: "SSL" or "TLS"
* `cipher_suite`: name of the negotiated cipher suite.
* `cipher_protocol_label`: protocol label (when available).
* `certificate_expires`: raw notAfter string from the certificate.
* `certificate_subject`: certificate subject (joined RDN pairs).
* `certificate_issuer`: certificate issuer (joined RDN pairs).

#### Collected Metrics

* `cypher_bits`: numeric cipher bit strength
* `remainig_days`: days until certificate expiry

#### Content
* Dashboards
    * Certificate-Checker-Overview
* Views
    * Certificate-Checker-DaysToExpire
    * Certificate-Checker-Protocols
    * Certificate-Checker-KeyLength
    * Certificate-Checker-Ciphers
* Reports
    * Certificate-Checker-Overview
* Alert Definitions
    *  Certificate-Checker-Cert-Expires

## Install

### Prerequisites
* abc
* xyz

### Installation Steps

1.  **step1**
    

2.  **Install dependencies:**

## Configure

To be done.
