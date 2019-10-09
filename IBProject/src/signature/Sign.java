package signature;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.implementations.RSAKeyValueResolver;
import org.apache.xml.security.keys.keyresolver.implementations.X509CertificateResolver;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import util.KeysUtils;

public class Sign {
	static {
	      Security.addProvider(new BouncyCastleProvider());
	      org.apache.xml.security.Init.init();
	  }
	private static final String KEY_STORE_FILE = "./data/usera.jks";

	public static Document signDocument(Document doc) {
		try {
			PrivateKey privateKey = KeysUtils.getPrivateKey("./data/usera.jks", "usera", "usera", "usera");

			Certificate cert = readCertificate();
			
			Element rootEl = doc.getDocumentElement();

			
			XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
			
			Transforms transforms = new Transforms(doc);

			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);

			transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);

			sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

			sig.addKeyInfo(cert.getPublicKey());
			sig.addKeyInfo((X509Certificate) cert);

			rootEl.appendChild(sig.getElement());
			sig.sign(privateKey);

			return doc;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static Certificate readCertificate() {
		try {
			
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");
			
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(KEY_STORE_FILE));
		
			ks.load(in, "usera".toCharArray());

			if (ks.isKeyEntry("usera")) {
				
				Certificate cert = ks.getCertificate("usera");
				return cert;

			} else
				return null;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static boolean verifySignature(Document doc) {

		try {
			
			NodeList signatures = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
			Element signatureEl = (Element) signatures.item(0);
			
			XMLSignature signature = new XMLSignature(signatureEl, null);

			
			KeyInfo keyInfo = signature.getKeyInfo();

			if (keyInfo != null) {
				keyInfo.registerInternalKeyResolver(new RSAKeyValueResolver());
				keyInfo.registerInternalKeyResolver(new X509CertificateResolver());

				if (keyInfo.containsX509Data() && keyInfo.itemX509Data(0).containsCertificate()) {
					Certificate cert = keyInfo.itemX509Data(0).itemCertificate(0).getX509Certificate();
					if (cert != null)
						return signature.checkSignatureValue((X509Certificate) cert);
					else
						return false;
				} else
					return false;
			} else
				return false;
		} catch (Exception e) {
			return false;
		}
	}
}
