package io.apizone.ips.simulation;


import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * @author imsrk
 * @project az-prc-ipsl
 * @timestamp Tuesday, 27-Jul-2021, 07:22
 */
public class XmlSigner {

    private static final String C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    private KeyStoreInfo keyStoreInfo;
    private InputStream sourceXml;


    // Create a DOM XMLSignatureFactory that will be used to
    // generate the enveloped signature.
    private static final XMLSignatureFactory fac     = XMLSignatureFactory.getInstance("DOM");

    /**
     * Signs a specific XML using a private key via Java Key Store format
     * <p>
     * More information:
     * https://gist.github.com/rponte/4039958
     * https://github.com/SUNET/eduid-mm-service/tree/master/src/main/java/se/gov/minameddelanden/common
     * https://stackoverflow.com/questions/5330049/java-equivalent-of-c-sharp-xml-signing-method
     *
     * @return the signed xml
     * @throws Exception the xml signing exception
     */
    public String sign() throws Exception {

        try {
            KeyStore keyStore               = keyStoreInfo.getKeyStore();
            String alias                    = keyStoreInfo.getAlias();
            char[] password                 = keyStoreInfo.getPassword().toCharArray();

            // Create a Reference to the enveloped document (in this case,
            // you are signing the whole document, so a URI of "" signifies
            // that, and also specify the SHA256 digest algorithm and
            // the ENVELOPED Transform.
            Transform envelopedTransform    = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
            Transform c14NEXCTransform      = fac.newTransform(C14N, (TransformParameterSpec) null);
            List<Transform> transforms      = Arrays.asList(envelopedTransform, c14NEXCTransform);

            DigestMethod digestMethod       = fac.newDigestMethod(DigestMethod.SHA256, null);
            Reference ref                   = fac.newReference("", digestMethod, transforms, null, null);

            // Create the SignedInfo.
            CanonicalizationMethod canonicalizationMethod   = fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
//            SignatureMethod signatureMethod                 = fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null);
            SignatureMethod signatureMethod                 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
            SignedInfo si                                   = fac.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(ref));

            // Create the KeyInfo containing the X509Data.
            KeyInfoFactory keyInfoFactory       = fac.getKeyInfoFactory();
            X509Certificate certificate         = (X509Certificate) keyStore.getCertificate(alias);

            X509Data newX509Data                = keyInfoFactory.newX509Data(Collections.singletonList(certificate));
            X509IssuerSerial issuer             = keyInfoFactory.newX509IssuerSerial(certificate.getIssuerX500Principal().getName(), certificate.getSerialNumber());

            List<XMLStructure> data             = Arrays.asList(newX509Data, issuer);
            KeyInfo keyInfo                     = keyInfoFactory.newKeyInfo(data);

            // Converts XML to Document
//            System.setProperty("javax.xml.parsers.DocumentBuilderFactory", "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");
            DocumentBuilderFactory dbf          = DocumentBuilderFactory.newInstance();
//            DocumentBuilderFactory dbf          = DocumentBuilderFactory.newInstance("com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl", this.getClass().getClassLoader());

            dbf.setNamespaceAware(true);
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            DocumentBuilder builder             = dbf.newDocumentBuilder();
            Document doc                        = builder.parse(sourceXml);

            // Create a DOMSignContext and specify the RSA PrivateKey and
            // location of the resulting XMLSignature's parent element.
            Key key                             = keyStore.getKey(alias, password);
            if (key == null) {
                throw new Exception(String.format("Private Key not found for alias '%s' in KS '%s'", alias, keyStore));
            }

            DOMSignContext dsc                  = new DOMSignContext(key, doc.getDocumentElement());
            // ds:SignatureValue
            dsc.setDefaultNamespacePrefix("ds");

            // Adds <Signature> tag before a specific tag inside XML - with or without namespace

            // Create the XMLSignature, but don't sign it yet.
            XMLSignature signature              = fac.newXMLSignature(si, keyInfo);
            signature.sign(dsc); // Marshal, generate, and sign the enveloped signature.

            this.removeWhitespaceFromSignature(doc);
            ByteArrayOutputStream output        = new ByteArrayOutputStream();
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            transformerFactory.newTransformer().transform(new DOMSource(doc), new StreamResult(output));


            String rawSignedXml                 = output.toString();
//            System.out.println("------- RAW SIGNED XML ---> " + rawSignedXml);
            return rawSignedXml;
//            return new SignedXml(rawSignedXml);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e.getMessage(), e);
        }

    }

    // https://stackoverflow.com/a/59220607
    private void removeWhitespaceFromSignature(Document document) {
        Element sig = (Element) document.getElementsByTagName("ds:SignatureValue").item(0);
        String sigValue = sig.getTextContent().replace("\r\n", "");
        sig.setTextContent(sigValue);

        Element cert = (Element) document.getElementsByTagName("ds:X509Certificate").item(0);
        String certValue = cert.getTextContent().replace("\r\n", "");
        cert.setTextContent(certValue);
    }

    /**
     * With key store xml signer.
     *
     * @param keyStore the key store
     * @param alias    the alias
     * @param password the password
     * @return the xml signer
     * @throws Exception the xml signing exception
     */
    public XmlSigner withKeyStore(InputStream keyStore, String alias, String password) throws Exception {
        KeyStoreInfo ksi = new KeyStoreInfo(alias, password);
        ksi.load(keyStore);

        this.keyStoreInfo = ksi;
        return this;
    }

    /**
     * With key store xml signer.
     *
     * @param keyStorePath the key store path
     * @param alias        the alias
     * @param password     the password
     * @return the xml signer
     * @throws IOException         the io exception
     * @throws Exception the xml signing exception
     */
    public XmlSigner withKeyStore(File keyStorePath, String alias, String password) throws IOException, Exception {

        return this.withKeyStore(new FileInputStream(keyStorePath), alias, password);
    }

    /**
     * With xml xml signer.
     *
     * @param sourceXml the source xml
     * @return the xml signer
     */
    public XmlSigner withXml(InputStream sourceXml) {
        Objects.requireNonNull(sourceXml, "Source xml cannot be null");
        this.sourceXml = sourceXml;
        return this;
    }

    /**
     * With xml xml signer.
     *
     * @param sourceXml the source xml
     * @return the xml signer
     * @throws IOException the io exception
     */
    public XmlSigner withXml(String sourceXml) throws IOException {
        try (InputStream input = new ByteArrayInputStream(sourceXml.getBytes(StandardCharsets.UTF_8))) {
            return withXml(input);
        }
    }
}


