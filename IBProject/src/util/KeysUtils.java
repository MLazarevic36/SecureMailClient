package util;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import keystore.KeyStoreReader;

public class KeysUtils {
	public static PrivateKey getPrivateKey(String path, String alias, String password, String keyPass) {
		KeyStoreReader ksr = new KeyStoreReader();
		try {
			return ksr.readKeyStore(path, alias, password.toCharArray(), keyPass.toCharArray()).getPrivateKey();
		} catch (ParseException e) {
			System.out.println("ERROR: PublicKey = NULL");
			return null;
		}		
	}
	
	public static PublicKey getPublicKey(String path, String alias, String password, String keyPass) {
		KeyStoreReader ksr = new KeyStoreReader();
		try {
			ksr.readKeyStore(path, alias, password.toCharArray(), keyPass.toCharArray());
			return ksr.readPublicKey();
		} catch (ParseException e) {
			System.out.println("ERROR: PublicKey = NULL");
			return null;
		}
	}
	
	public static SecretKey generateSessionKey() {
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			return keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			return null;
		} 
		
	}
}
