package com.lifetracker.urls;

import com.lifetracker.session.Encryption;
import com.lifetracker.session.SessionFactory;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.binary.StringUtils;
import org.bson.Document;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.mongodb.Block;
import com.mongodb.DB;
import com.mongodb.MongoClient;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;

import lombok.Setter;

import static com.mongodb.client.model.Filters.eq;

@Component
@Path("/login")
public class login {
	@Autowired
	SessionFactory sessionFactory = new SessionFactory();
	MongoClient mongoClient = new MongoClient("localhost", 27017);

	@GET
	@Produces("application/json")
	public Response defaultlogin() throws JSONException {

		StringBuilder sb = new StringBuilder();
		sb.append("ANKARA");

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("original", sb.toString());
		jsonObject.put("reversed", sb.reverse().toString());

		String result = "" + jsonObject;
		return Response.status(200).entity(result).build();
	}

	@Path("/fblogin")
	@POST
	@Produces("application/json")
	public Response fblogin(@FormParam("userid") String fbUserId, @FormParam("emailid") String emailId,
			@FormParam("username") String userName, @FormParam("accessToken") String accessToken,
			@FormParam("code") String code) throws JSONException {
		System.out.println("fblogin fbuserId:" + fbUserId + "emailId:" + emailId + "userName:" + userName
				+ "accessToken" + accessToken + "code" + code);
		if(emailId==null || fbUserId ==null || userName==null){
			JSONObject jsonObject = new JSONObject();
			jsonObject.put("action", "username&email&fbuseridcannotbenull");
			return Response.status(200).entity("" + jsonObject).build();
		}
		return signInTheUser(emailId, userName, fbUserId, null, false);
	}

	private Response signInTheUser(String emailId, String userName, String fbUserId, String password,
			boolean passwordCheck) {
		// TODO Auto-generated method stub

		if (emailId == null) {
			JSONObject jsonObject = new JSONObject();
			jsonObject.put("action", "email cant be null");
			return Response.status(200).entity("" + jsonObject).build();
		}
		/*
		 * for fb login step1: check authenticity of user details
		 */
		MongoCollection<Document> user_detail_collection = mongoClient.getDatabase("mydb")
				.getCollection("user_detail_collection");
		MongoCollection<Document> sessionCollection = mongoClient.getDatabase("mydb")
				.getCollection("sessioncollection");

		// check if user exists in collection
		Document user_detail_document = user_detail_collection.find(eq("emailId", emailId)).first();
		String userId;
		System.out.println("user existing document:" + user_detail_document);

		// check if user exists
		if (user_detail_document != null && !user_detail_document.isEmpty()) {
			userId = user_detail_document.getString("userId");
			System.out.println("user_detail exists");

			// for email login check password
			if (passwordCheck) {
				if (!StringUtils.equals(password, user_detail_document.getString("password"))) {
					JSONObject jsonObject = new JSONObject();
					jsonObject.put("action", "invalidPassword");
					return Response.status(200).entity("" + jsonObject).build();
				}
			}

			// user exists so check for session
			Document sessionDocument = sessionCollection.find(eq("userId", userId)).first();

			// check for session
			if (sessionDocument != null && !sessionDocument.isEmpty()) {
				System.out.println("user has session");
				// add new jwtsession
				List<String> encryptedJWTList = (List<String>) sessionDocument.get("encryptedJWT");
				String encryptedJWTSession = sessionFactory.getNewEncryptedJWT(userId, userName, emailId);
				encryptedJWTList.add(encryptedJWTSession);
				sessionDocument.remove("encryptedJWT");
				sessionDocument.append("encryptedJWT", encryptedJWTList);
				sessionCollection.updateOne(eq("userId", userId), new Document().append("$set", sessionDocument));
				// send single non array encrypted jwt to user
				sessionDocument.remove("encryptedJWT");
				sessionDocument.append("encryptedJWT", encryptedJWTSession).append("action", "jwt");
				return Response.status(200).entity("" + sessionDocument.toJson()).build();

			} else {

				System.out.println("user no session");
				// add new session
				String encryptedJWTSession = sessionFactory.getNewEncryptedJWT(userId, userName, emailId);

				Document userSessionDocument = new Document().append("userId", userId).append("encryptedJWT",
						Arrays.asList(encryptedJWTSession));
				sessionCollection.insertOne(userSessionDocument);

				// send single non array encrypted jwt to user
				userSessionDocument.remove("encryptedJWT");
				userSessionDocument.append("encryptedJWT", encryptedJWTSession).append("action", "jwt");
				return Response.status(200).entity("" + sessionDocument.toJson()).build();
			}

		} else {
			System.out.println("user doesnt exist");
			if (passwordCheck) {
				JSONObject jsonObject = new JSONObject();
				jsonObject.put("action", "invalidUser");
				return Response.status(200).entity("" + jsonObject).build();
			}

			System.out.println("creating new user");
			// user doesn't exist so add new user and user session and return
			// jwt

			// adding new user to user_detail_collection
			// {"userid":"12321313","userName":"ramu",
			// "emailId":"ads@asd.asd","fbUserId":"sdfs32424"}
			return createNewUserAndSession(emailId, userName, fbUserId, password, sessionCollection);

		}
	}

	private Response createNewUserAndSession(String emailId, String userName, String fbUserId, String password,
			MongoCollection<Document> sessionCollection) {
		Document newUserDocument = createNewUser(emailId, userName, fbUserId, password);
		System.out.println("newUserDocument" + newUserDocument);

		String encryptedJWTSession = sessionFactory.getNewEncryptedJWT(newUserDocument.getString("userId"), userName,
				emailId);

		Document userSessionDocument = new Document().append("userId", newUserDocument.getString("userId"))
				.append("encryptedJWT", Arrays.asList(encryptedJWTSession));
		sessionCollection.insertOne(userSessionDocument);

		// send single non array encrypted jwt to user
		userSessionDocument.remove("encryptedJWT");
		userSessionDocument.append("encryptedJWT", encryptedJWTSession).append("action", "jwt");
		mongoClient.close();
		return Response.status(200).entity("" + userSessionDocument.toJson()).build();
	}

	private Document createNewUser(String emailId, String userName, String fbUserId, String password) {
		// if useremail exists needs to be tested before calling this function
		MongoCollection<Document> usercollection = mongoClient.getDatabase("mydb")
				.getCollection("user_detail_collection");
		Document newUserdocument = new Document().append("userId", String.valueOf(getTime())).append("emailId", emailId)
				.append("userName", userName).append("fbUserId", fbUserId).append("password", password);
		usercollection.insertOne(newUserdocument);
		return newUserdocument;
	}

	@Path("/emaillogin")
	@POST
	@Produces("application/json")
	public Response emailSignIn(@FormParam("emailid") String emailId, @FormParam("password") String userPassword)
			throws JSONException {
		System.out.println("emailSignIn user emailId:" + emailId + " password" + userPassword);
		if(emailId==null || userPassword ==null ){
			JSONObject jsonObject = new JSONObject();
			jsonObject.put("action", "email&passwordcannotbenull");
			return Response.status(200).entity("" + jsonObject).build();
		}
		return signInTheUser(emailId, null, null, userPassword, true);
	}

	@Path("/createnewuser")
	@POST
	@Produces("application/json")
	public Response createnewuser(@FormParam("emailid") String emailId, @FormParam("password") String userPassword,
			String userName) throws JSONException {
		System.out.println("emailSignIn user emailId:" + emailId + " password" + userPassword + " username" + userName);
		if(emailId==null || userPassword ==null || userName==null){
			JSONObject jsonObject = new JSONObject();
			jsonObject.put("action", "username&email&passwordcannotbenull");
			return Response.status(200).entity("" + jsonObject).build();
		}
		// check if user exists
		MongoCollection<Document> user_detail_collection = mongoClient.getDatabase("mydb")
				.getCollection("user_detail_collection");
		Document user_detail_document = user_detail_collection.find(eq("emailId", emailId)).first();
		String userId;
		System.out.println("user existing document:" + user_detail_document);
		if (user_detail_document != null && !user_detail_document.isEmpty()) {
			JSONObject jsonObject = new JSONObject();
			jsonObject.put("action", "userExists");
			return Response.status(200).entity("" + jsonObject).build();
		} else {
			MongoCollection<Document> sessionCollection = mongoClient.getDatabase("mydb")
					.getCollection("sessioncollection");
			return createNewUserAndSession(emailId, userName, null, userPassword, sessionCollection);
		}
	}

	static synchronized long getTime() {
		return System.nanoTime();
	}

}