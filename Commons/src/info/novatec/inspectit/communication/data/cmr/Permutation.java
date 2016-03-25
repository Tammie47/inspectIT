package info.novatec.inspectit.communication.data.cmr;

import org.apache.commons.codec.binary.Hex;

import info.novatec.inspectit.util.PermutationException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class to encapsulate all cryptographic methods for the login process.
 * All methods rely on the harmony of the static final values.
 * 
 * @author Andreas Herzog
 *
 */
public abstract class Permutation {
	/**
	 * Default value. Changing the algorithm requires testing.
	 */
	public static final String SYMMETRIC_ALGORITHM = "AES";
	/**
	 * Default value. Should not be changed.
	 */
	public static final int SYMMETRIC_KEY_SIZE = 128;
	/**
	 * Default value. Changing the algorithm requires testing.
	 */
	public static final String ASYMMETRIC_ALGORITHM = "RSA";
	/**
	 * Default value. Should not be changed.
	 */
	public static final int ASYMMETRIC_KEY_SIZE = 2048;
	/**
	 * Default value. Should not be changed.
	 */
	public static final String STANDART_CHARSET = "UTF-8";
	
	/**
	 * Generates a random symmetric key.
	 * @return SecretKey (byte-encoded)
	 * @throws PermutationException (Exception wrapper)
	 */
	public static byte[] generateSecretKey() throws PermutationException {
		KeyGenerator kg;
		try {
			kg = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
			kg.init(SYMMETRIC_KEY_SIZE);
			return kg.generateKey().getEncoded();
		} catch (NoSuchAlgorithmException nsaEx) {
			throw new PermutationException(nsaEx.getMessage());
		}
	}
	
	/**
	 * Encrypts the public key in order to send it.
	 * @param pk public key from the CMR
	 * @param secretKey randomly generated symmetric key
	 * @return PublicKey (byte-encoded)
	 * @throws PermutationException (Exception wrapper)
	 */
	public static byte[] encryptPublicKey(PublicKey pk, byte[] secretKey) throws PermutationException {
		RSAPublicKey publicKey = (RSAPublicKey) pk;
		String firstPart = publicKey.getModulus().toString();
		String secondPart = publicKey.getPublicExponent().toString();
		try {
			Cipher c = Cipher.getInstance(SYMMETRIC_ALGORITHM);
			SecretKeySpec sks = new SecretKeySpec(secretKey, SYMMETRIC_ALGORITHM);
			SecretKey sk = sks;
			c.init(Cipher.ENCRYPT_MODE, sk);
			byte[] combination = (firstPart + "|" + secondPart).getBytes(STANDART_CHARSET);
			return c.doFinal(combination);
		} catch (Exception e) {
			throw new PermutationException(e.getClass().getName() + " - " +  e.getMessage());
		}
	}
	
	/**
	 * Decodes the encoded PublicKey.
	 * @param publicKeyBytes encoded PublicKey
	 * @param secretKey encoded SecretKey
	 * @return byte-encoded PublicKey
	 * @throws PermutationException (Exception wrapper)
	 */
	public static byte[] decodePublicKey(byte[] publicKeyBytes, byte[] secretKey) throws PermutationException {
		try {
			Cipher c = Cipher.getInstance(SYMMETRIC_ALGORITHM);
			SecretKeySpec sks = new SecretKeySpec(secretKey, SYMMETRIC_ALGORITHM);
			SecretKey sk = sks;
			c.init(Cipher.DECRYPT_MODE, sk);
			
			String combination = new String(c.doFinal(publicKeyBytes));
			String [] parts = combination.split("\\|");
			String firstPart = parts[0];
			String secondPart = parts[1];

			RSAPublicKeySpec spec = new RSAPublicKeySpec(
			        new BigInteger(firstPart),
			        new BigInteger(secondPart));
			
			return KeyFactory.getInstance(ASYMMETRIC_ALGORITHM).generatePublic(spec).getEncoded();
		} catch (Exception e) {
			throw new PermutationException(e.getClass().getName() + " - " +  e.getMessage());
		}
	}
	
	/**
	 * Encrypts a String using a byte-encoded PublicKey.
	 * @param theHash String
	 * @param publicKeyBytes byte-encoded PublicKey
	 * @return encrypted String (byte-encoded)
	 * @throws PermutationException (Exception wrapper)
	 */
	public static byte[] encryptStringWithPublicKey(String theHash, byte[] publicKeyBytes) throws PermutationException {
		Cipher cipher;
		PublicKey pk;
		try {
			cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
			pk = KeyFactory.getInstance(ASYMMETRIC_ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKeyBytes));
			cipher.init(Cipher.ENCRYPT_MODE, pk);
			return cipher.doFinal(theHash.getBytes(STANDART_CHARSET));
		} catch (Exception e) {
			throw new PermutationException(e.getClass().getName() + " - " +  e.getMessage());
		}
	}
	
	/**
	 * Encrypts a byte-encoded SecretKey using a byte-encoded PublicKey.
	 * @param secretKeyBytes byte-encoded SecretKey
	 * @param publicKeyBytes byte-encoded PublicKey
	 * @return encrypted byte[] of the SecretKey
	 * @throws PermutationException (Exception wrapper)
	 */
	public static byte[] encryptSecretKey(byte[] secretKeyBytes, byte[] publicKeyBytes) throws PermutationException {
		Cipher cipher;
		PublicKey publicKey;
		try {
			cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
			publicKey = KeyFactory.getInstance(ASYMMETRIC_ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKeyBytes));
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(secretKeyBytes);
		} catch (Exception e) {
			throw new PermutationException(e.getClass().getName() + " - " +  e.getMessage());
		}
	}
	
	/**
	 * Encrypts a byte[] using a byte-encoded SecretKey.
	 * @param content the content
	 * @param secretKeyBytes byte-encoded SecretKey
	 * @return encrypted byte[]
	 * @throws PermutationException (Exception wrapper)
	 */
	public static byte[] encryptWithSecretKey(byte[] content, byte[] secretKeyBytes) throws PermutationException {
		Cipher cipher;
		SecretKey secretKey;
		try {
			cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
			SecretKeySpec sks = new SecretKeySpec(secretKeyBytes, SYMMETRIC_ALGORITHM);
			secretKey = sks;
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			return cipher.doFinal(content);
		} catch (Exception e) {
			throw new PermutationException(e.getClass().getName() + " - " +  e.getMessage());
		}
	}

	/**
	 * Decodes the SecretKey using the PrivateKey of the CMR.
	 * @param encryptedSecretKey byte-encoded SecretKey
	 * @param privateKeyBytes byte-encoded PrivateKey
	 * @return decoded SecretKey
	 * @throws PermutationException (Exception wrapper)
	 */
	public static byte[] decodeSecretKeyWithPrivateKey(byte[] encryptedSecretKey, byte[] privateKeyBytes) throws PermutationException {
		Cipher cipher;
		PrivateKey privateKey;
		try {
			cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
			privateKey = KeyFactory.getInstance(ASYMMETRIC_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(encryptedSecretKey);
		} catch (Exception e) {
			throw new PermutationException(e.getClass().getName() + " - " +  e.getMessage());
		}
	}
	
	/**
	 * Restores the hash form of the password.
	 * @param encryptedSecretKey from client
	 * @param secondEncryptionLevel password, which was encrypted two times.
	 * @param privateKeyBytes PrivateKey of the CMR (byte-encoded)
	 * @return String representing the password hash.
	 * @throws PermutationException (Exception wrapper)
	 */
	public static String decryptPassword(byte[] encryptedSecretKey, byte[] secondEncryptionLevel, byte[] privateKeyBytes) throws PermutationException {
		Cipher cipher;
		PrivateKey privateKey;
		SecretKey secretKey;
		try {
			privateKey = KeyFactory.getInstance(ASYMMETRIC_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
			
			byte[] secretKeyBytes = decodeSecretKeyWithPrivateKey(encryptedSecretKey, privateKey.getEncoded());
			SecretKeySpec sks = new SecretKeySpec(secretKeyBytes, SYMMETRIC_ALGORITHM);
			secretKey = sks;
			
			cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] decryptedOnce = cipher.doFinal(secondEncryptionLevel);
			
			cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			
			return new String(cipher.doFinal(decryptedOnce));
			
		} catch (Exception e) {
			throw new PermutationException(e.getClass().getName() + " - " +  e.getMessage());
		}
	}

	/**
	 * Hashes a passed String using SHA-256 algorithm.
	 * 
	 * @param password
	 *            as String
	 * @return byte[] of the password
	 * @throws NoSuchAlgorithmException
	 *             should not happen.
	 */
	private static byte[] hash(String password) throws NoSuchAlgorithmException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] passBytes = password.getBytes();
		byte[] hash = sha256.digest(passBytes);
		return hash;
	}

	/**
	 * Hashes a passed String using SHA-256 algorithm.
	 * 
	 * @param password
	 *            as String
	 * @return hex-encoded hash of the password
	 */
	public static String hashString(String password) {
		try {
			return new String(Hex.encodeHex(hash(password)));
		} catch (NoSuchAlgorithmException nsaEx) {
			return "";
		}
	}
}
