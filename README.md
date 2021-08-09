Generate Certificate Store (PKCS)
---
1. Transport Certificate Store
    openssl pkcs12 -export -in bank8888_transport.pem -inkey bank8888.key -name bank8888_transport -out bank8888_transport.p12

2. Seal Certificate Store
    openssl pkcs12 -export -in bank8888_seal.pem -inkey bank8888.key -name bank8888_seal -out bank8888_seal.p12

Update Variables & Parameters in `SignXml.java`
---
1. Replace CERT_SEAL_LOCATION, CERT_SEAL_ALIAS, CERT_SEAL_PASSWORD with your SEAL Certificate and Password
2. Replace CERT_TRNS_LOCATION and CERT_TRNS_PASSWORD with your Transport Cerificate and Password
3. Replace IPS Application URL for Verification and Credit Transfer under variable IPS_API_URL_CR and IPS_API_URL_VER
4. Create request payloads and update variable for REQUEST_PAYLOAD_CR and REQUEST_PAYLOAD_VER
