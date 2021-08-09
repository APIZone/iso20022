package io.apizone.ips.simulation;


import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;




public class IPSAPIInvoker {


	//Test Parameters & Constants
	private static String DEFUALT_VERB 				= "POST";
	private static String DEFUALT_STORE_TYPE 		= "PKCS12";
	private static String DEFUALT_CONTENT_TYPE 		= "application/xml";




	/*********************************************************************
	 * @param sslURL: HTTPS Endpoint 
	 * @param certStorePath: Certificate Store (JKS) path on the Host OS
	 * @param certStorePassword: Password for the Certificate Store
	 * @param apiKey: Unique API Key assigned for accessing this Endpoint
	 * @param authToken: Associated authorization tokens
	 * @param readTimeout: Sets a specified timeout value, in milliseconds, to be used when reading from Input stream of a established connection to a resource
	 * @param connectTimeout: Sets a specified timeout value, in milliseconds, to be used when opening a communications link to the resource referenced by the URLConnection 
	 * @return API response payload, in case of errors (HTTP Response Code >= 400) a short error summary is returned from server. This can be further customized under block 'Handle ERROR Scenario'
	 * @throws Upstream Exception
	 **********************************************************************/

	public static String sendHttpsGetRequest(String sslURL, String certStorePath, String certStorePassword, String requestPayload){

		System.out.println("[" + Calendar.getInstance().getTime() +  "] ======= A. Invoking ISO20022 API: " + sslURL);


		try {
			// Client Keystore
			System.setProperty("javax.net.ssl.keyStoreType", 		DEFUALT_STORE_TYPE);
			System.setProperty("javax.net.ssl.keyStore", 			certStorePath);
			System.setProperty("javax.net.ssl.keyStorePassword", 	certStorePassword);

			// Client Truststore
			System.setProperty("javax.net.ssl.trustStoreType", 		DEFUALT_STORE_TYPE);
			System.setProperty("javax.net.ssl.trustStore", 			certStorePath);
			System.setProperty("javax.net.ssl.trustStorePassword",  certStorePassword);




			/*** https://www.rgagnon.com/javadetails/java-fix-certificate-problem-in-HTTPS.html ***/

			//1. Override Hostname Verification
			HostnameVerifier hv = new HostnameVerifier() {
				public boolean verify(String urlHostName, SSLSession session) {

					return true;
				}
			};
			HttpsURLConnection.setDefaultHostnameVerifier(hv);


			//2. Trust All Certificates
			/*TrustManager[] trustAllCerts = new TrustManager[] {
		       new X509TrustManager() {
		          public java.security.cert.X509Certificate[] getAcceptedIssuers() {
		            return null;
		          }

		          public void checkClientTrusted(X509Certificate[] certs, String authType) {  }

		          public void checkServerTrusted(X509Certificate[] certs, String authType) {  }

		       }
		    };

		    SSLContext sc = SSLContext.getInstance("SSL");
		    sc.init(null, trustAllCerts, new java.security.SecureRandom());
		    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());*/

			
			final KeyStore truststore 	= readStore(certStorePath, certStorePassword);

			final SSLContext sslContext;
			try {
				sslContext 				= SSLContexts.custom()
										 .loadTrustMaterial(truststore, new TrustAllStrategy())
										 .loadKeyMaterial(truststore, certStorePassword.toCharArray(), (aliases, socket) -> "1")
										 .build();
			} catch (Exception e) {
				throw new RuntimeException("Failed to read keystore", e);
			}
			
			
			CloseableHttpClient httpClient 		= HttpClients.custom().setSSLContext(sslContext).build();	
			HttpPost httpPost 					= new HttpPost(sslURL);
			
			StringEntity entity 				= new StringEntity(requestPayload);
		    httpPost.setEntity(entity);
		    httpPost.setHeader("Accept", 		DEFUALT_CONTENT_TYPE);
		    httpPost.setHeader("Content-type", 	DEFUALT_CONTENT_TYPE);
		    
			HttpResponse response 				= httpClient.execute(httpPost);
			System.out.println("======= IPS ISO20022 HTTP RESPONSE: " + response.getStatusLine().getStatusCode());


		} catch(Exception e) {
			
		}
			return "";

	}



	private static KeyStore readStore(String keyStorePath, String keyStorePass) {
		
		KeyStore keyStore 					= null;
		try (InputStream keyStoreStream 	= new FileInputStream(keyStorePath)) {
			keyStore 				= KeyStore.getInstance("PKCS12"); // or "JKS"
			keyStore.load(keyStoreStream, 	keyStorePass.toCharArray());
		} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keyStore;

	}



	//Test API Call
	public static void main(String[] args) {

		//TODO: Remove below, just kept for testing
		String CERT_LOCATION 	= "/Users/imsrk/Documents/Projects/IPSL-PaaS/PoC/api-CSR-poc/csr/certs-STAGE-CONVERTER-8888/KeyStore/PKCS/bank8888_transport.p12"; 
		String CERT_PASSWORD	= "@Bc12345";
		String STR_URL 			= "https://api.stage.pesalink.co.ke/iso20022/async/v1/credit-transfer"; 
		String REQUEST_PAYLOAD  = "/Users/imsrk/Documents/Projects/IPSL-MicroServices/ips-simulation/src/main/resources/iso20022/credit-transfer.txt";

		sendHttpsGetRequest(STR_URL, CERT_LOCATION, CERT_PASSWORD, REQUEST_PAYLOAD);	


	}




}
