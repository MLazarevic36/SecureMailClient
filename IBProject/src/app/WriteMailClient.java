package app;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.api.services.gmail.Gmail;

import signature.Sign;
import support.MailHelper;
import support.MailWritter;
import util.KeysUtils;
import util.XmlUtils;

public class WriteMailClient extends MailClient {
	static {
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

	public static void main(String[] args) {

		try {
			Gmail service = getGmailService();
			
			System.out.println("Insert a reciever:");
			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			String reciever = reader.readLine();

			System.out.println("Insert a subject:");
			String subject = reader.readLine();

			System.out.println("Insert body:");
			String body = reader.readLine();
			
			
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("mail");
			rootElement.setTextContent(body);
			doc.appendChild(rootElement);
			

			Sign.signDocument(doc);
			
		
			SecretKey secretKey = KeysUtils.generateSessionKey();
			
			PublicKey publicKey = KeysUtils.getPublicKey("./data/userb.jks", "userb", "userb", "userb");

			
			XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

		
			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
			keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
		
		
			EncryptedKey encryptedKey = keyCipher.encryptKey(doc, secretKey);
			System.out.println("Kriptovan tajni kljuc: " + encryptedKey);
			
			
			KeyInfo keyInfo = new KeyInfo(doc);
			keyInfo.addKeyName("Kriptovani tajni kljuc");
			keyInfo.add(encryptedKey);		
		

			EncryptedData encryptedData = xmlCipher.getEncryptedData();
			encryptedData.setKeyInfo(keyInfo);
			
			
			xmlCipher.doFinal(doc, rootElement, true);

			String encryptedXml = XmlUtils.DocToString(doc);
			System.out.println("Mail posle enkripcije: " + encryptedXml);
			

			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, subject, encryptedXml);
			MailWritter.sendMessage(service, "me", mimeMessage);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
