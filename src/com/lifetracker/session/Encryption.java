package com.lifetracker.session;

import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
	
	static Cipher cipher,desCipher;
	static String encryptKey = "lStephenDSouza";
	
	public String encrypt(String nonEncrypted)  {
		try {
			return  new String(getCipher().doFinal(nonEncrypted.getBytes("UTF-8")),"ISO-8859-1");
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public String decrypt(String encryptedString) {
		

	    try {
			return new String(getDeCipher().doFinal(encryptedString.getBytes("ISO-8859-1")));
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	private Cipher getDeCipher() {
		if (desCipher == null) {
			KeyGenerator keygenerator;
			try {
				 SecretKeySpec myDesKey =new SecretKeySpec(encryptKey.getBytes(), "Blowfish");
				// Create the cipher
				 desCipher = Cipher.getInstance("Blowfish");
				// Initialize the cipher for encryption
				 desCipher.init(Cipher.DECRYPT_MODE, myDesKey);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return desCipher;
	}

	private Cipher getCipher() {

		if (cipher == null) {

			KeyGenerator keygenerator;
			try {

				 SecretKeySpec myDesKey =new SecretKeySpec(encryptKey.getBytes(), "Blowfish");
				// Create the cipher
				cipher = Cipher.getInstance("Blowfish");
				// Initialize the cipher for encryption
				cipher.init(Cipher.ENCRYPT_MODE, myDesKey);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return cipher;

	}

}
