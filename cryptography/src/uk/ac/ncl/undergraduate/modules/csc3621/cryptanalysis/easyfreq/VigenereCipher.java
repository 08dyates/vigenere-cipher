package uk.ac.ncl.undergraduate.modules.csc3621.cryptanalysis.easyfreq;

/**
 * This class is capable of encrypt and decrypt according to the Vigenere
 * cipher.
 *
 * @author Changyu Dong
 * @author Roberto Metere
 * @author Dalton Yates
 */
public class VigenereCipher {

	/**
	 * Encryption function of the Vigenere cipher.
	 *
	 * @param plaintext
	 *            the plaintext to encrypt
	 * @param key
	 *            the encryption key
	 * @return the ciphertext according with the Vigen&egrave;re cipher.
	 */
	public static String encrypt(String plaintext, String key) {

		plaintext = plaintext.toUpperCase();
		StringBuilder ciphertextSB = new StringBuilder(plaintext);
		char temp;
		int keyLength = key.length();
		char newChar;

		// go through each character in the plain text
		for (int i = 0; i < plaintext.length(); i++) {

			temp = plaintext.charAt(i);

			// if the character is a letter, change it to the new encrypted letter
			if (Util.isValidLetter(temp)) {
				newChar = Util.indexToChar(
						Util.mod(Util.charToIndex(temp) + Util.charToIndex(key.charAt(i % keyLength)), 26));
				ciphertextSB.setCharAt(i, newChar) ;

			}
		}

		return ciphertextSB.toString();
		
	}

	/**
	 * Decryption function of the Vigenere cipher.
	 *
	 *
	 * @param ciphertext
	 *            the encrypted text
	 * @param key
	 *            the encryption key
	 * @return the plaintext according with the Vigenere cipher.
	 */
	public static String decrypt(String ciphertext, String key) {

		ciphertext = ciphertext.toUpperCase();
		StringBuilder plaintextSB = new StringBuilder(ciphertext);
		char temp;
		int keyLength = key.length();
		char newChar;
		
		// go through every letter in cipher text
		for (int i = 0; i < ciphertext.length(); i++) {
			temp = ciphertext.charAt(i);

			// if character is a letter, change it to new decrypted letter
			if (Util.isValidLetter(temp)) {
				newChar = Util.indexToChar(
						Util.mod(Util.charToIndex(temp) - Util.charToIndex(key.charAt(i % keyLength)), 26));
				plaintextSB.setCharAt(i, newChar);
			} 
		}
		
		return plaintextSB.toString();
	}

}
