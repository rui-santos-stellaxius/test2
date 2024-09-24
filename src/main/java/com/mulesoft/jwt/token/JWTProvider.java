package com.mulesoft.jwt.token;


import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.commons.codec.binary.Base64;
import java.text.MessageFormat;
import java.security.*; 


public class JWTProvider {
	
	private static final Logger logger = LogManager.getLogger("JWTProvider - Start");
	public static String getToken(String PRIVATE_KEY_FILE_RSA, String PRIVATE_KEY_PASSWORD, String SF_CONSUMER_KEY, String SF_EMAIL, String AUDIENCE_URL) throws Exception {
		
		logger.debug("Generating JWS token");
		
		String header = "{\"alg\":\"RS256\"}";
	    String claimTemplate = "'{'\"iss\": \"{0}\", \"sub\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\", \"jti\": \"{4}\"'}'";
	    StringBuffer token = new StringBuffer();
	   
	    try {
	      

	      //Encode the JWT Header and add it to our string to sign
	      token.append(Base64.encodeBase64URLSafeString(header.getBytes("UTF-8")));

	      //Separate with a period
	      token.append(".");

	      //Create the JWT Claims Object
	      String[] claimArray = new String[5];
	      claimArray[0] = SF_CONSUMER_KEY;
	      claimArray[1] = SF_EMAIL;
	      claimArray[2] = AUDIENCE_URL;
	      claimArray[3] = Long.toString( ( System.currentTimeMillis()/1000 ) + 300);
	      claimArray[4] = UUID.randomUUID().toString();
	      MessageFormat claims;
	      claims = new MessageFormat(claimTemplate);
	      String payload = claims.format(claimArray);

	      //Add the encoded claims object
	      token.append(Base64.encodeBase64URLSafeString(payload.getBytes("UTF-8")));

	      //Load the private key from a keystore
	      KeyStore keystore = KeyStore.getInstance("JKS");
	      URL resource = JWTProvider.class.getClassLoader().getResource(PRIVATE_KEY_FILE_RSA);
		  FileInputStream is = new FileInputStream(new File(resource.toURI()));
	      keystore.load(is, PRIVATE_KEY_PASSWORD.toCharArray());
	      PrivateKey privateKey = (PrivateKey) keystore.getKey("mulesoft_oauth_jwt", PRIVATE_KEY_PASSWORD.toCharArray());

	      //Sign the JWT Header + "." + JWT Claims Object
	      Signature signature = Signature.getInstance("SHA256withRSA");
	      signature.initSign(privateKey);
	      signature.update(token.toString().getBytes("UTF-8"));
	      String signedPayload = Base64.encodeBase64URLSafeString(signature.sign());

	      //Separate with a period
	      token.append(".");

	      //Add the encoded signature
	      token.append(signedPayload);

	      //System.out.println(token.toString());
	      

	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    return (token.toString());
		
	}

}
