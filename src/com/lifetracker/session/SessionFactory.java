package com.lifetracker.session;

import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.springframework.stereotype.Component;

import com.lifetracker.session.Encryption;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

@Component
public class SessionFactory {
	String JWTKey = "JWTKey";
	Encryption jwtEncryption = new Encryption();
	
	public String getNewEncryptedJWT(String userId,String userName, String emailId) {
		try {
			String jwtToken =  JWT.create().withClaim("userId", userId).withClaim("username", userName).withClaim("emailId", emailId)
					.withIssuedAt(new Date()).sign(Algorithm.HMAC256(JWTKey));
			return jwtEncryption.encrypt(jwtToken);
		} catch (IllegalArgumentException | JWTCreationException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public JWT verifyEncryptedJWT(String encryptedJWT){
		String decryptedToken = jwtEncryption.decrypt(encryptedJWT);
		return JWT.decode(decryptedToken);
	}

}
