package com.moxtra.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.Charset;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.xml.security.utils.Base64;
import org.codehaus.jackson.map.ObjectMapper;
import com.moxtra.util.MultipartUtility;


public class MoxtraAPIUtil {
	public static String UNIQUEID_GRANT_TYPE = "http://www.moxtra.com/auth_uniqueid"; 
	public static String API_HOST_URL = "https://api.moxtra.com/";
	public static String WEB_HOST_URL = "https://www.moxtra.com/";
	public static String PARAM_ACCESS_TOKEN = "access_token";
	public static String PARAM_EXPIRES_IN = "expires_in";
	
	
	/**
	 * To get the Access Token via /oauth/token unique_id. The return in the following JSON format
	 *   
	 *   {
	 *   	"access_token": ACCESS_TOKEN,
	 *   	"expires_in": EXPIRES_IN,
	 *   	...
	 *   }
	 * 
	 * @param client_id
	 * @param client_secret
	 * @param unique_id
	 * @param firstname (optional)
	 * @param lastname (optional) 
	 * @return HashMap    
	 * @throws MoxtraAPIUtilException
	 */
	
	public static HashMap<String, Object> getAccessToken(String client_id, String client_secret, String unique_id,
			String firstname, String lastname) throws MoxtraAPIUtilException {
		
		if (client_id == null || client_secret == null || unique_id == null) {
			throw new MoxtraAPIUtilException("client_id, client_secret, and unique_id are required!"); 
		}
		
		String timestamp = Long.toString(System.currentTimeMillis());
		HashMap<String, Object> myMap = new HashMap<String, Object>();
		
		try {

			// generate code
			Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
			
			SecretKeySpec secret_key = new SecretKeySpec(client_secret.getBytes(), "HmacSHA256");
			sha256_HMAC.init(secret_key);
			
			StringBuffer total = new StringBuffer();
			total.append(client_id);
			total.append(unique_id);
			total.append(timestamp);		
			
			String signature = new String(encodeUrlSafe(sha256_HMAC.doFinal(total.toString().getBytes()))).trim();			
			
			HttpClient httpClient = new DefaultHttpClient();
			HttpPost httpPost = new HttpPost(API_HOST_URL + "oauth/token");
			// Request parameters and other properties.
			List<NameValuePair> params = new ArrayList<NameValuePair>();
			params.add(new BasicNameValuePair("client_id", client_id));
			params.add(new BasicNameValuePair("client_secret", client_secret));
			params.add(new BasicNameValuePair("grant_type", UNIQUEID_GRANT_TYPE));
			params.add(new BasicNameValuePair("uniqueid", unique_id));
			params.add(new BasicNameValuePair("timestamp", timestamp));
			params.add(new BasicNameValuePair("signature", signature));
			
			// optional
			if (firstname != null) {
				params.add(new BasicNameValuePair("firstname", firstname));
			}
			
			if (lastname != null) {
				params.add(new BasicNameValuePair("lastname", lastname));
			}
		    httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
		    
		    HttpResponse response = httpClient.execute(httpPost);		    
			HttpEntity responseEntity = response.getEntity(); 
			if (response.getStatusLine().getStatusCode() != 200) {
				throw new Exception("unable to get access_token");
			}
			if (responseEntity != null) {
		        // EntityUtils to get the response content
		        String content =  EntityUtils.toString(responseEntity);
                
                // get access token
                ObjectMapper objectMapper = new ObjectMapper();
        		myMap = objectMapper.readValue(content, HashMap.class);
                
            } else {
            	throw new Exception("unable to make request");
            }
            
    		return myMap;		
            
  		} catch (Exception e) {
  			throw new MoxtraAPIUtilException(e.getMessage(), e);
  		}
		
	}
	
	/**
	 * upload Binder Cover page
	 * 
	 * @param binder_id
	 * @param uploadImage
	 * @param access_token
	 * @return Binder info in JSON
	 * @throws MoxtraAPIUtilException
	 */
	
	
	public static String uploadBinderCover(String binder_id, File uploadImage, String access_token) throws MoxtraAPIUtilException {
		
		if (binder_id == null || uploadImage == null || access_token == null) {
			throw new MoxtraAPIUtilException("binder_id, uploadImage, and access_token are required!"); 
		}
		
		String requestURL = API_HOST_URL + binder_id + "/coverupload?access_token=" + access_token;
		
		try {
			MultipartUtility multipart = new MultipartUtility(requestURL, "UTF-8");
			
			multipart.addFilePart("file", uploadImage);

			List<String> response = multipart.finish();
			
			//System.out.println("SERVER REPLIED:");
			
			StringBuffer result = new StringBuffer();
			for (String line : response) {
				//System.out.println(line);
				result.append(line);
			}
			
			return result.toString();
			
		} catch (IOException ex) {
			throw new MoxtraAPIUtilException("unable to upload image", ex);
		}
	}
	
	
	/**
	 * Upload page into Binder
	 * 
	 * @param binder_id
	 * @param uploadFile
	 * @param access_token
	 * @return Binder page info in JSON
	 * @throws MoxtraAPIUtilException
	 */
	
	public static String uploadBinderPage(String binder_id, File uploadFile, String access_token) throws MoxtraAPIUtilException {
		
		if (binder_id == null || uploadFile == null || access_token == null) {
			throw new MoxtraAPIUtilException("binder_id, uploadFile, and access_token are required!"); 
		}
		
		String requestURL = API_HOST_URL + binder_id + "/pageupload?access_token=" + access_token;
		
		try {
			MultipartUtility multipart = new MultipartUtility(requestURL, "UTF-8");
			
			multipart.addFilePart("file", uploadFile);

			List<String> response = multipart.finish();
			
			//System.out.println("SERVER REPLIED:");
			
			StringBuffer result = new StringBuffer();
			for (String line : response) {
				//System.out.println(line);
				result.append(line);
			}
			
			return result.toString();
			
		} catch (IOException ex) {
			throw new MoxtraAPIUtilException("unable to upload page file", ex);
		}
	}
	

	/**
	 * Upload current user's picture
	 * 
	 * @param uploadImage
	 * @param access_token
	 * @return update status in JSON
	 * @throws MoxtraAPIUtilException
	 */
	
	public static String uploadUserPicture(File uploadImage, String access_token) throws MoxtraAPIUtilException {
		
		if (uploadImage == null || access_token == null) {
			throw new MoxtraAPIUtilException("uploadImage and access_token are required!"); 
		}
		
		String requestURL = API_HOST_URL + "me/picture?access_token=" + access_token;
		
		try {
			MultipartUtility multipart = new MultipartUtility(requestURL, "UTF-8");
			
			multipart.addFilePart("file", uploadImage);

			List<String> response = multipart.finish();
			
			//System.out.println("SERVER REPLIED:");
			
			StringBuffer result = new StringBuffer();
			for (String line : response) {
				//System.out.println(line);
				result.append(line);
			}
			
			return result.toString();
			
		} catch (IOException ex) {
			throw new MoxtraAPIUtilException("unable to upload user picture", ex);
		}
	}
	

	/**
	 * upload File into Meet based on session_id and session_key for host
	 * 
	 * @param session_id
	 * @param session_key
	 * @param uploadFile
	 * @param access_token
	 * @return response in JSON
	 * @throws MoxtraAPIUtilException
	 */
	
	public static String uploadFileToMeet(String session_id, String session_key, File uploadFile, String access_token) 
		throws MoxtraAPIUtilException {
		
		if (session_id == null || session_key == null || uploadFile == null || access_token == null) {
			throw new MoxtraAPIUtilException("session_id, session_key, uploadFile, and access_token are required!"); 
		}
		
		String json_result = null;
		InputStream inputStream = null;

		try {

			String filename = URLEncoder.encode(uploadFile.getName(), "UTF-8");		
			String requestURL = WEB_HOST_URL + "board/upload?type=original&session_id=" + session_id + "&key=" + session_key + "&name=" + filename + "&access_token=" + access_token;
			
			inputStream = new FileInputStream(uploadFile);
			
			long length = uploadFile.length();
			
			HttpClient httpClient = new DefaultHttpClient();
			HttpPost httppost = new HttpPost(requestURL);
			InputStreamEntity entity = new InputStreamEntity(inputStream, length, ContentType.APPLICATION_OCTET_STREAM);
			httppost.setEntity(entity);
			
			HttpResponse response = httpClient.execute(httppost);
			HttpEntity responseEntity = response.getEntity(); 
			if (response.getStatusLine().getStatusCode() != 200) {
				throw new Exception("Upload file failed");
			}
			if (responseEntity != null) {
				json_result = EntityUtils.toString(responseEntity);
			}
			
			return json_result;
		
  		} catch (Exception e) {
  			throw new MoxtraAPIUtilException(e.getMessage(), e);
  			
		} finally {
			
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException ex) {
					throw new MoxtraAPIUtilException(ex.getMessage(), ex);
				}
			}
			
		}
		
	}
	
	/**
	 * create a binder with json_input String
	 * 
	 * @param json_input
	 * @param access_token
	 * @return response in JSON
	 * @throws MoxtraAPIUtilException
	 */
	
	public static String createBinder(String json_input, String access_token) throws MoxtraAPIUtilException {
		
		if (json_input == null || access_token == null) {
			throw new MoxtraAPIUtilException("json and access_token are required!"); 
		}
		
		String json_result = null;
		
		try {
			String requestURL = API_HOST_URL + "me/binders?access_token=" + access_token;
			
			HttpClient httpClient = new DefaultHttpClient();
			HttpPost httppost = new HttpPost(requestURL);
			
			ContentType contentType = ContentType.create("application/json", Charset.forName("UTF-8"));
			StringEntity entity = new StringEntity(json_input, contentType);
			httppost.setEntity(entity);
			
			HttpResponse response = httpClient.execute(httppost);
			HttpEntity responseEntity = response.getEntity(); 
			if (response.getStatusLine().getStatusCode() != 200) {
				throw new Exception("Upload file failed");
			}
			if (responseEntity != null) {
				json_result = EntityUtils.toString(responseEntity);
			}
			
			return json_result;
		
  		} catch (Exception e) {
  			throw new MoxtraAPIUtilException(e.getMessage(), e);
  		}
		
	}
	
	/**
	 * URLSafe Base64 encoding with space padding 
	 * 
	 * @param data
	 * @return
	 */
	public static byte[] encodeUrlSafe(byte[] data) {
	    String strcode = Base64.encode(data);
	    byte[] encode = strcode.getBytes(); 
	    for (int i = 0; i < encode.length; i++) {
	        if (encode[i] == '+') {
	            encode[i] = '-';
	        } else if (encode[i] == '/') {
	            encode[i] = '_';
	        } else if (encode[i] == '=') {
	        	encode[i] = ' ';
	        }
	    }
	    return encode;
	}	

}
