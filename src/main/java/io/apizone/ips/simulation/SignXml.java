package io.apizone.ips.simulation;



import java.security.KeyStore;
import java.util.Calendar;
import java.io.*;



/**
 * @author imsrk
 * @project ipsl-simulation
 * @timestamp Tuesday, 27-Jul-2021, 07:51
 */


public class SignXml {

	//Seal
    private static final String CERT_SEAL_LOCATION  	= "/Users/imsrk/Documents/Projects/IPSL-PaaS/PoC/api-CSR-poc/csr/certs-STAGE-CONVERTER-8888/KeyStore/PKCS/bank8888_seal.p12";
    private static final String CERT_SEAL_ALIAS     	= "bank8888_seal";
    private static final String CERT_SEAL_PASSWORD  	= "@Bc12345";
    
    //Transport
    private static final String CERT_TRNS_LOCATION 		= "/Users/imsrk/Documents/Projects/IPSL-PaaS/PoC/api-CSR-poc/csr/certs-STAGE-CONVERTER-8888/KeyStore/PKCS/bank8888_transport.p12"; 
    private static final String CERT_TRNS_PASSWORD		= "@Bc12345";
    
    //IPS Payload & Endpoints
    private static final String IPS_API_URL_CR 			= "https://api.stage.pesalink.co.ke/iso20022/async/v1/credit-transfer";
    private static final String IPS_API_URL_VER 		= "https://api.stage.pesalink.co.ke/iso20022/async/v1/verification-request";

    //Payload RAW
    private static final String REQUEST_PAYLOAD_CR  	= "/Users/imsrk/Documents/Projects/IPSL-MicroServices/ips-simulation/src/main/resources/iso20022/credit-transfer.txt";
    private static final String REQUEST_PAYLOAD_VER 	= "/Users/imsrk/Documents/Projects/IPSL-MicroServices/ips-simulation/src/main/resources/iso20022/IdVrfctnReq.txt";


    
    
    public static void main(String[] args) {

        String signedXML 				= getSignedMessage(REQUEST_PAYLOAD_VER);
        System.out.println("[" + Calendar.getInstance().getTime() +  "] ------- Signed XML --->\n" + signedXML);
        
        IPSAPIInvoker.sendHttpsGetRequest(IPS_API_URL_VER, CERT_TRNS_LOCATION, CERT_TRNS_PASSWORD, signedXML);



    }


	private static String getSignedMessage(String requestPayloadPlainText) {
		KeyStore keyStore;
		String signedXML				= "";

        try {
            FileInputStream fisKeyStore = new java.io.FileInputStream(CERT_SEAL_LOCATION);
            FileInputStream fisRequest  = new java.io.FileInputStream(requestPayloadPlainText);
            XmlSigner xmlSigner         = new XmlSigner().withKeyStore(fisKeyStore, CERT_SEAL_ALIAS, CERT_SEAL_PASSWORD).withXml(fisRequest);
            signedXML            		= xmlSigner.sign();
            

        } catch(Exception e){
            e.printStackTrace();
        }
		return signedXML;
	}
    
    
    
}
