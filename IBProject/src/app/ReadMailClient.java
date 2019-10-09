package app;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;


import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.encryption.XMLCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import signature.Sign;
import support.MailHelper;
import support.MailReader;
import util.KeysUtils;
import util.XmlUtils;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	static {
        Security.addProvider(new BouncyCastleProvider());
        org.apache.xml.security.Init.init();
	}
	
	public static void main(String[] args) throws Exception {
		
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        

        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
		String xmlAsString = MailHelper.getText(chosenMessage);
		
		Document doc = XmlUtils.StringToDoc(xmlAsString);
		
		
		PrivateKey prvateKey = KeysUtils.getPrivateKey("./data/userb.jks", "userb", "userb", "userb");
		
		
		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
		

		xmlCipher.setKEK(prvateKey);
		
	
		NodeList encDataList = doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
		Element encData = (Element) encDataList.item(0);
		
	
		xmlCipher.doFinal(doc, encData); 
		

		System.out.println("Verified: " + Sign.verifySignature(doc));
		
	
		String msg = doc.getElementsByTagName("mail").item(0).getTextContent();
		System.out.println("Body text: " + (msg.split("\n"))[0]);
		
	}	
}