package com.sbi.tcs;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

//import com.ibm.misc.BASE64Decoder;
//import com.ibm.misc.BASE64Encoder;

public class thirdPartyNpci {
	
	static String jkspwd,enpass= "";
 	static String base64PrivateKey,base64publickey = null;
 	static HashMap<String, String> hashmap_public = new HashMap<>();

	
//	static String certpath =  "/opt/IBM/EndPoint_Public/NPCISigner.cer";
	static String jkspath="/opt/IBM/RSAKeystore/ibmdevportal.jks";
	static String propertiesPath="/opt/IBM/PropertyFile/KeyMapper.properties";

	public static void main(String[] args) throws Exception {
		String Message1 = digitalSignature("This is EIS");
		System.out.println(Message1);
	}

//	public static String Sign(String message) throws Exception {
//	public static String Sign(String message) {
//		try {
//			// Creating Modulus and Exponent
//			FileInputStream fis = new FileInputStream(certpath);
//			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//			X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fis);
//			fis.close();
//
//			PublicKey publicKey = certificate.getPublicKey();
//			java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicKey;
//
//			byte[] modulusBytes = rsaPublicKey.getModulus().toByteArray();
//			byte[] exponentBytes = rsaPublicKey.getPublicExponent().toByteArray();
////			String signature = Sign(message, modulusBytes, exponentBytes);
////			System.out.println("DigitalSign:" + signature);
//
//			// sign the message
//			RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new java.math.BigInteger(modulusBytes),
//					new java.math.BigInteger(exponentBytes));
//			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
//
//			Signature signature = Signature.getInstance("SHA256withRSA");
//			signature.initSign(privateKey);
//			signature.update(message.getBytes());
//
//			byte[] signatureBytes = signature.sign();
//			String Modulus64 = Base64.getEncoder().encodeToString(modulusBytes);
//			String Exponent64 = Base64.getEncoder().encodeToString(exponentBytes);
////		System.out.println(Modulus64);
////		System.out.println(Exponent64);
//			String digiSign = digitalSignature(message);
//			String wDigisign = digiSign + "," + Modulus64 + "," + Exponent64;
//			return wDigisign;
//		} catch (Exception e) {
//			return e.toString();
//		}
//	}
//	
	public static String VerifySign(String message, String Modulus, String Exponent) {
		try {
			byte[] modulusBytes = Base64.getDecoder().decode(Modulus);
			byte[] exponentBytes = Base64.getDecoder().decode(Exponent);
		RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new java.math.BigInteger(modulusBytes),
				new java.math.BigInteger(exponentBytes));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(message.getBytes());
		byte[] signatureBytes = signature.sign();
		String digiSign = Base64.getEncoder().encodeToString(signatureBytes);

		return digiSign;
		}
		catch (Exception e) {
			return e.toString();
		}
	}
	
	public static String getProperty(String key,String propertiesPath)
	{		
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(propertiesPath));
			Properties p = new Properties();
			p.load(reader);
			return p.getProperty(key);
      		} 		
		catch (Exception e){			
      		return "X-JavaError" +" " +e.toString();			
		    }	     	
   	}
	
	public static String digitalSignature(String data)
	{   
		byte[] encData= new byte[100];
		String str="";
		String modulus="";
		String exponent="";
		try {	
		 /*if (base64PrivateKey  == null)
	     {	
	     	base64PrivateKey = getPrivateKey();	
	     }*/
		 	base64PrivateKey = getPrivateKey();	
		 	//change .replaceAll("\r\n", "")
		    byte[] privebase64decKey = Base64.getDecoder().decode(base64PrivateKey);
		    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privebase64decKey);
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");	        
	        Signature privateSignature = Signature.getInstance("SHA256withRSA");
	        PrivateKey privaKey = keyFactory.generatePrivate(keySpec);
	        //this is to get modulus and exponent
	        
//	    	java.security.interfaces.RSAPrivateKey rsaPrivateKey = (java.security.interfaces.RSAPrivateKey) publicKey;
	    	
	    				
	        
	        
	        RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privaKey, RSAPrivateKeySpec.class);
	        byte[] modulusBytes = rsaPrivateKeySpec.getModulus().toByteArray();
	        byte[] exponentBytes = rsaPrivateKeySpec.getPrivateExponent().toByteArray();
	        
	        modulus = Base64.getEncoder().encodeToString(modulusBytes);
			exponent = Base64.getEncoder().encodeToString(exponentBytes);
	        
	        
	        
	        
	        
	        
//	        modulus = rsaPrivateKeySpec.getModulus().toString();
//	        exponent = rsaPrivateKeySpec.getPrivateExponent().toString();
	        
	        privateSignature.initSign(privaKey);
	        privateSignature.update(data.getBytes("UTF-8"));
	        byte[] s = privateSignature.sign();	  
	        
	     
	        encData = Base64.getEncoder().encode(s);  
	        
	         str = new String(encData,StandardCharsets.UTF_8).replaceAll("\r\n", "");
		} catch (Exception e) {
			return "X-JavaError" +" " +e.toString();
		}	   
	   return str+","+modulus+","+exponent;						  
	}
	public static String AESDecrypt(String message, String key) 
	   {		  
	 	  try {	 			 
	 		byte [] keybyte = key.getBytes("UTF-8"); 
		 	byte [] ivkey = Arrays.copyOf(keybyte,16);
	 		IvParameterSpec iv = new IvParameterSpec(ivkey);
	 		byte[] encvalue = Base64.getDecoder().decode(message);
	 		SecretKeySpec seckey= new SecretKeySpec(keybyte, "AES");
	 		Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	 		c.init(2,seckey,iv);
	 		byte[] decvalue=c.doFinal(encvalue);
	 		String decryptedvalue = new String(decvalue);
	 		return decryptedvalue;	 			 		
	 	} catch (Exception e) {	 	
	 		return "X-JavaError" +" " +e.toString();
	 	}	 	  
	   }	
	
	public static String getPrivateKey()
	{
	 		try {
	 			jkspwd = getProperty("aesk", propertiesPath); 
	 			enpass = getProperty("enpass", propertiesPath);
	    		boolean isAliasWithPrivateKey = false;
				KeyStore keyStore = KeyStore.getInstance("JKS");
				jkspwd = AESDecrypt(enpass, jkspwd);				
				if (!jkspwd.contains("X-JavaError"))
				{
				keyStore.load(new FileInputStream(jkspath), jkspwd.toCharArray());	             
				Enumeration<String> es = keyStore.aliases();
				String alias = "";
				while (es.hasMoreElements()) {
					alias = (String) es.nextElement();
					if (isAliasWithPrivateKey = keyStore.isKeyEntry(alias)) {
						break;
					}
				}				
				if (isAliasWithPrivateKey) {
					KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
					new KeyStore.PasswordProtection(jkspwd.toCharArray()));
					PrivateKey myPrivateKey = pkEntry.getPrivateKey();
					byte[] privateKey= (myPrivateKey.getEncoded());
				    base64PrivateKey = DatatypeConverter.printBase64Binary(privateKey);
				    }
				}
				else
				{
					base64PrivateKey = 	jkspwd + " : Error in Decryption of keystore password";
				}				
	 		}
		catch (Exception e)
		{
      		return "X-JavaError" +" " +e.toString();
		}
	     return base64PrivateKey;	
   	}
	public static String getPublicKey(String certPath)
	{
	 		try {
	 			FileInputStream fin = new FileInputStream(certPath);
				CertificateFactory f = CertificateFactory.getInstance("X.509");
				X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
				PublicKey publicKey = certificate.getPublicKey();
				byte[] pk = publicKey.getEncoded();
			    base64publickey = DatatypeConverter.printBase64Binary(pk);
			   fin.close();	 
	 		}				
		catch (Exception e)
		{			
      		return "X-JavaError" +" " +e.toString();			
		    }
	     return base64publickey;	
   	}
	
	
}
/////////////////////////////////////////////////////////////

package com.sbi.tcs;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;
import com.ibm.broker.plugin.MbXMLNSC;
import com.ibm.misc.BASE64Decoder;

public class ThirdPartyGenericComplaintUdir_sys_JavaCompute extends MbJavaComputeNode {
	
	static String jkspath="/opt/IBM/RSAKeystore/ibmdevportal.jks";
	static String propertiesPath="/opt/IBM/PropertyFile/KeyMapper.properties";
	static String jkspwd,enpass= "";
	
	private KeyStore.PrivateKeyEntry keyEntry;
	public void evaluate(MbMessageAssembly inAssembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");
		
		MbMessage inMessage = inAssembly.getMessage();
		MbMessageAssembly outAssembly = null;
		try {
			int ccsid = 0;
			// create new message as a copy of the input
			MbMessage outMessage = new MbMessage();
			outAssembly = new MbMessageAssembly(inAssembly, outMessage);
		
			MbElement outRoot = outMessage.getRootElement();
			MbElement xmlMessage = inMessage.getRootElement().getLastChild();  
			byte[] xml = xmlMessage.toBitstream(null, null, null, 0, ccsid, 0);
			String msg = new String(xml);		
			String SignatureValue = new String(createDigitalSignature(msg));
			
			MbElement outParser = outRoot.createElementAsLastChild(MbXMLNSC.PARSER_NAME);		
			outParser.createElementAsLastChild(MbElement.TYPE_VALUE,"DigiSign",SignatureValue);		         
			
		} catch (MbException e) {			
			throw e;
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new MbUserException(this, "evaluate()", "", "", e.toString(),
					null);
		}		
		
		out.propagate(outAssembly);
	}

		
	public String createDigitalSignature(String message) throws Exception {
	    String outPut="";
		try{
			
//			this.keyEntry = getKeyFromKeyStore();
//			this.keyEntry = getPrivateKey();
			
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document inputDocument = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(message)));
			Document signedDocument = generateSignValue(inputDocument,true);
      
			StringWriter stringWriter = new StringWriter();
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(signedDocument), new StreamResult(stringWriter));
//			outPut = stringWriter.getBuffer().toString();
	      
		}
		catch (Exception e){
			throw new RuntimeException("Error while digitally signing the XML document", e);
		}		
		
		return outPut;
	}
	
	
	private KeyStore.PrivateKeyEntry getKeyFromKeyStore() {
	    InputStream keyFileStream = null;
	    jkspwd = getProperty("aesk", propertiesPath); 
			enpass = getProperty("enpass", propertiesPath);
			jkspwd = AESDecrypt(enpass, jkspwd);
	    try {
				String KeystorePathValue = getUserDefinedAttribute("/opt/IBM/RSAKeystore/ibmdevportal.jks").toString();
				System.out.println(jkspwd);
				String KeystorePasswordValue = getUserDefinedAttribute(jkspwd).toString();
				String KeystoreAliasNameValue = getUserDefinedAttribute("").toString();
				char[] password = KeystorePasswordValue.toCharArray();
				KeyStore ks = KeyStore.getInstance("jks");
	  	        keyFileStream = new FileInputStream(KeystorePathValue);
			    ks.load(keyFileStream, password);
			    KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry)ks.getEntry(KeystoreAliasNameValue, new KeyStore.PasswordProtection(password));
			    System.out.println(key);
	            return key;
	    }
	    catch (Exception e) {
	      e.printStackTrace();
	      return null;
	    } finally {
	      if (keyFileStream != null) {
	        try {
	          keyFileStream.close();
	        } catch (IOException e) {
	          e.printStackTrace();
	        } 
	      }
	    } 
	  }
	
	static String base64PrivateKey, base64publickey = null;
	
	public static String getPrivateKey() {
		try {
			jkspwd = getProperty("aesk", propertiesPath);
			enpass = getProperty("enpass", propertiesPath);
			boolean isAliasWithPrivateKey = false;
			KeyStore keyStore = KeyStore.getInstance("JKS");
			jkspwd = AESDecrypt(enpass, jkspwd);
			if (!jkspwd.contains("X-JavaError")) {
				keyStore.load(new FileInputStream(jkspath), jkspwd.toCharArray());
				Enumeration<String> es = keyStore.aliases();
				String alias = "";
				while (es.hasMoreElements()) {
					alias = (String) es.nextElement();
					if (isAliasWithPrivateKey = keyStore.isKeyEntry(alias)) {
						break;
					}
				}
				if (isAliasWithPrivateKey) {
					KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
							new KeyStore.PasswordProtection(jkspwd.toCharArray()));
					PrivateKey myPrivateKey = pkEntry.getPrivateKey();
					byte[] privateKey = (myPrivateKey.getEncoded());
					base64PrivateKey = DatatypeConverter.printBase64Binary(privateKey);
				}
			} else {
				base64PrivateKey = jkspwd + " : Error in Decryption of keystore password";
			}
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return base64PrivateKey;
	}
		
	public Document generateSignValue(Document xmlDoc, boolean includeKeyInfo) throws Exception {
	    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");	    
	    Reference ref = fac.newReference("", fac.newDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256", null), 
	        Collections.singletonList(fac
	          .newTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature", (TransformParameterSpec)null)), null, null);
	    
	    SignedInfo sInfo = fac.newSignedInfo(fac.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", (C14NMethodParameterSpec)null), fac
	        .newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null), 
	        
	    Collections.singletonList(ref));  
	    	    
	    if (this.keyEntry == null) {
	      throw new RuntimeException("Key could not be read for digital signature. Please check value of signature alias and signature password, and restart the Auth Client");
	    }	    
	    X509Certificate x509Cert = (X509Certificate)this.keyEntry.getCertificate();    
	    KeyInfo kInfo = getKeyInfo(fac, x509Cert.getPublicKey());
	    DOMSignContext dsc = new DOMSignContext(this.keyEntry.getPrivateKey(), xmlDoc.getDocumentElement());
	    XMLSignature signature = fac.newXMLSignature(sInfo, includeKeyInfo ? kInfo : null);
	    signature.sign(dsc);
	    
	    Node node = dsc.getParent();	  
	    return node.getOwnerDocument();
	  }
	
	private KeyInfo getKeyInfo(XMLSignatureFactory xmlSigFactory, PublicKey publicKey) {
	    KeyValue keyValue = null;
	    KeyInfoFactory keyInfoFact = xmlSigFactory.getKeyInfoFactory();
	    try {
	      keyValue = keyInfoFact.newKeyValue(publicKey);
	    } catch (KeyException ex) {
	      ex.printStackTrace();
	    } 
	    return keyInfoFact.newKeyInfo(Collections.singletonList(keyValue));
	  }
	public static String getProperty(String key,String propertiesPath)
	{		
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(propertiesPath));
			Properties p = new Properties();
			p.load(reader);
			return p.getProperty(key);
      		} 		
		catch (Exception e){			
      		return "X-JavaError" +" " +e.toString();			
		    }	     	
   	}
	
	public static String AESDecrypt(String message, String key) {
		try {
			byte[] keybyte = key.getBytes("UTF-8");
			byte[] ivkey = Arrays.copyOf(keybyte, 16);
			IvParameterSpec iv = new IvParameterSpec(ivkey);
			byte[] encvalue = new BASE64Decoder().decodeBuffer(message);
			SecretKeySpec seckey = new SecretKeySpec(keybyte, "AES");
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			c.init(2, seckey, iv);
			byte[] decvalue = c.doFinal(encvalue);
			String decryptedvalue = new String(decvalue);
			return decryptedvalue;
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

}
