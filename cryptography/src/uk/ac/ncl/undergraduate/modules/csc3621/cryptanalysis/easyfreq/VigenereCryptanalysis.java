package uk.ac.ncl.undergraduate.modules.csc3621.cryptanalysis.easyfreq;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Paths;

/**
 * This class is for frequency cryptanalysis of ciphertext.
 *
 * @author Changyu Dong
 * @author Roberto Metere
 * @author Dalton Yates
 */
public class VigenereCryptanalysis {

	/**
	 * The ciphertext (encryption of the plaintext).
	 */
	private String ciphertext;

	/**
	 * The plaintext (readable content).
	 */
	private String plaintext;

	/**
	 * The key such that the encryption of the plaintext with such key gives the
	 * ciphertext.
	 */
	private final StringBuffer key = new StringBuffer();

	/**
	 * This variable is just to run the script interactive, that is with manual
	 * tunes.
	 */
	private boolean interactive;

	/**
	 * INTERACTIVE means that you can manually tune the analysis and/or the
	 * result.
	 */
	public static final boolean INTERACTIVE = true;

	/**
	 * AUTOMATIC means that the analysis will not ask any further information.
	 */
	public static final boolean AUTOMATIC = false;

	/**
	 * Create an new class to cryptanalyze texts.
	 */
	public VigenereCryptanalysis() {
	}

	/**
	 * Constructor with interactive choice.
	 *
	 * @param interactive
	 *            whether it should ask for manual tuning or not
	 */
	public VigenereCryptanalysis(boolean interactive) {
		this.interactive = interactive;
	}

	/**
	 * Set the ciphertext to analyse.
	 *
	 * @param text
	 *            the text to set as
	 */
	public void setCiphertext(String text) {
		this.ciphertext = text;
	}

	/**
	 * This method is to allow you to manually set the key can be used as a
	 * subroutine in your cryptanalysis for manual adjustment
	 */
	private void manualAdjustment() {

		int answer;
		int index;
		char letter;

		do {
			System.out.println("How do you want to change the key (1: insert, 2:replace, 3:delete, 4:nothing)? ");
			answer = Util.reader.nextInt();
		} while (answer < 1 || answer > 4);

		switch (answer) {
		case 1:
			System.out.println("Enter the index where you want to insert the key charater");
			index = Util.reader.nextInt();
			System.out.println("Enter the letter you want to insert");
			letter = Util.reader.next().charAt(0);
			if (index < 0 || index > this.key.length()) {
				System.out.println("Index out of range");
			} else if (!Util.isValidLetter(letter)) {
				System.out.println("key character must be a letter");
			} else {
				this.key.insert(index, letter);

			}
			break;

		case 2:
			System.out.println("Enter the index of the character you want to replace");
			index = Util.reader.nextInt();
			System.out.println("Enter the new character");
			letter = Util.reader.next().charAt(0);
			if (index < 0 || index >= this.key.length()) {
				System.out.println("Index out of range");
			} else if (!Util.isValidLetter(letter)) {
				System.out.println("key character must be a letter");
			} else {
				this.key.replace(index, index, Character.toString(letter));
			}
			break;

		case 3:
			System.out.println("Enter the index of the character you want to delete");
			index = Util.reader.nextInt();
			if (index < 0 || index >= this.key.length()) {
				System.out.println("Index out of range");
			} else {

				this.key.deleteCharAt(index);

			}
			break;

		default:
			break;
		}
	}

	/**
	 * This method conducts cryptanalysis of the frequency of letters in the
	 * ciphertext to retrieve the encryption key.
	 *
	 * @return the key as result of the cryptanalysis
	 */
	public String cryptanalysis() {
		
		final int keysToTry = 30;
		double[] allIC = new double[keysToTry];
		int keyLength = 0;
		double bestIC = 0;
		

		// get an array of all average index of coincidence
		for (int i = 0; i < keysToTry; i++) {
			allIC[i] = findAverageIC(i + 2);
		}
		
		// find the best IC and the key length of the key
		for (int i = 0; i < keysToTry; i++) {
			if (allIC[i] > bestIC) {
				bestIC = allIC[i];
				keyLength = i + 2;
			}
		}

		FrequencyCryptanalysis fC = new FrequencyCryptanalysis();
		
		// key letters
		for (int i = 0; i < keyLength; i++) {
			StringBuffer tryCiphertextSB = new StringBuffer();
			// get ciphertext that only includes the ith + keyLength character
			for (int j = 0; j < ciphertext.length(); j++) {
				if (i == (j % keyLength)) {
					tryCiphertextSB.append(ciphertext.charAt(j));
				}
			}
			//perform cryptanalysis on the string to find each letter of the key
			fC.setCiphertext(tryCiphertextSB.toString());
			key.append(Util.indexToChar(fC.cryptanalysis()));
		}

		
		// The following code allows you to manually adjust your result.
		if (this.interactive) {
			String answer;
			do {

				do {
					System.out.println("Do you want to see the plaintext (Y/N)? ");
					answer = Util.reader.next().toUpperCase();
				} while (!(answer.equals("Y") || answer.equals("N")));

				if (answer.equals("Y")) {
					this.decrypt();
					System.out.println(this.plaintext);
				}

				do {
					System.out.println("Do you want to see the key (Y/N)? ");
					answer = Util.reader.next().toUpperCase();
				} while (!(answer.equals("Y") || answer.equals("N")));

				if (answer.equals("Y")) {
					System.out.println(this.key);
				}

				do {
					System.out.println("Do you want to change the key (Y/N)? ");
					answer = Util.reader.next().toUpperCase();
				} while (!(answer.equals("Y") || answer.equals("N")));

				if (answer.equals("Y")) {
					this.manualAdjustment();
				}

				do {
					System.out.println("Do you want to stop (Y/N)? ");
					answer = Util.reader.next().toUpperCase();
				} while (!(answer.equals("Y") || answer.equals("N")));

			} while (!answer.equals("Y"));
		}

		return this.key.toString();
	}

	/**
	 * Method to find the average Index of Coincidence of the cipher text given
	 * a key length
	 * 
	 * @param keyLength
	 * @return average Index of Coincidence
	 */
	private double findAverageIC(int keyLength) {
		double averageIC = 0;
		StringBuffer ithCharacters = new StringBuffer();
		double sum = 0;

		// create an array of ICs for the key length.
		for (int i = 0; i < keyLength; i++) {

			// find IC for each index of the key
			for (int j = 0; j < ciphertext.length(); j++) {
				if (i == (j % keyLength)) {
					ithCharacters.append(ciphertext.charAt(j));
				}
			}
			// find sum of all ICs
			sum += findICOfString(ithCharacters.toString());
		}

		// find average of ICs
		averageIC = sum / keyLength;

		return averageIC;
	}

	/**
	 * Method to find the Index of Coincidence of a string
	 * 
	 * @param text
	 * @return index of coincidence
	 */
	public double findICOfString(String text) {
		double IC;
		double sumOfFrequencies = 0;
		int N = Util.countLetters(text);
		FrequencyAnalyser fA = new FrequencyAnalyser();

		// Get table of frequencies of letters in text
		fA.setText(text);
		double[] table = fA.analyse().getTable();

		// get sum of frequencies
		for (double i : table) {
			sumOfFrequencies += (i * N) * (i * N - 1);

		}
		// find index of coincidence
		IC = sumOfFrequencies / (N * (N - 1));

		return IC;
	}

	/**
	 * This method reconstructs the plaintext from the ciphertext with the key.
	 */
	public void decrypt() {
		this.plaintext = VigenereCipher.decrypt(this.ciphertext, this.key.toString());
	}

	/**
	 * Show the results of the complete analysis.
	 */
	public void showResult() {
		System.out.println("The key is " + this.key.toString());
		this.decrypt();
		System.out.println("The plaintext is:");
		System.out.println(this.plaintext);
	}

	/**
	 * @param args
	 *            the command line arguments
	 * @throws java.io.IOException
	 *             errors reading from files
	 * @throws java.net.URISyntaxException
	 *             Errors in retrieving resources
	 */
	public static void main(String[] args) throws IOException, URISyntaxException {
		String mainPath, ciphertextFilePath, ciphertext;
		VigenereCryptanalysis cryptanalysis;
		File solutionDirectory;
		String solutionKeyFilePath, solutionPlaintextFilePath;

		// Add argument -i at run to enable interactive mode (and disable
		// automatic mode)
		if (0 < args.length && args[0].equals("-i")) {
			cryptanalysis = new VigenereCryptanalysis(INTERACTIVE);
		} else {
			cryptanalysis = new VigenereCryptanalysis(AUTOMATIC);
		}

		// Get resources
		mainPath = Paths.get(FrequencyCryptanalysis.class.getResource("/").toURI()).toString();
		ciphertextFilePath = mainPath + "/res/Exercise2Ciphertext.txt";
		solutionDirectory = new File(mainPath + "/solution2");
		solutionKeyFilePath = solutionDirectory + "/key.txt";
		solutionPlaintextFilePath = solutionDirectory + "/plaintext.txt";

		// Do the job
		ciphertext = Util.readFileToBuffer(ciphertextFilePath);
		cryptanalysis.setCiphertext(ciphertext);
		cryptanalysis.cryptanalysis();
		cryptanalysis.showResult();

		// Write solution in res path
		if (!solutionDirectory.exists()) {
			solutionDirectory.mkdir();
		}
		Util.printBufferToFile(cryptanalysis.key.toString(), solutionKeyFilePath);
		Util.printBufferToFile(cryptanalysis.plaintext, solutionPlaintextFilePath);
	}
}
