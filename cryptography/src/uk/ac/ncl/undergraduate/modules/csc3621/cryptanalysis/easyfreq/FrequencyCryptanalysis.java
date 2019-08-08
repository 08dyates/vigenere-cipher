package uk.ac.ncl.undergraduate.modules.csc3621.cryptanalysis.easyfreq;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Paths;

/**
 * This class is for frequency cryptanalysis of ciphertext when the key is an
 * integer.
 *
 * @author Changyu Dong
 * @author Roberto Metere
 * @author Dalton Yates
 */
public class FrequencyCryptanalysis {

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
	private int key;

	/**
	 * Frequency table (of the ciphertext).
	 */
	private FrequencyTable table;

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
	 * This variable is just to run the script interactive, that is with manual
	 * tunes.
	 */
	private boolean interactive = AUTOMATIC;

	/**
	 * Set the ciphertext to analyse.
	 *
	 * @param text
	 *            the text to set as ciphertext
	 */
	public void setCiphertext(String text) {
		this.ciphertext = text;
	}

	/**
	 * Create an new class to cryptanalyze texts.
	 */
	public FrequencyCryptanalysis() {
	}

	/**
	 * Constructor with interactive choice.
	 *
	 * @param interactive
	 *            whether it should ask for manual tuning or not
	 */
	public FrequencyCryptanalysis(boolean interactive) {
		this.interactive = interactive;
	}

	/**
	 * This method is to allow you to manually set the key can be used as a
	 * subroutine in your cryptanalysis for manual adjustment
	 */
	private void manualAdjustment() {
		int i;

		System.out.println("Enter the key (0-25): ");
		i = Util.reader.nextInt(); // Scans the next token of the input as an
									// int.
		if (i >= 0 && i <= 25) {
			this.key = i;
			System.out.println("The key is set to " + this.key);
		} else {
			System.out.println("The key is invalid (must be an integer between 0 and 25 included).");
		}
	}

	/**
	 * This method conducts cryptanalysis of the frequency of letters in the
	 * ciphertext to retrieve the encryption key.
	 *
	 *
	 * @return the key as the result of the cryptanalysis
	 */
	public int cryptanalysis() {
		/**
		 * Method for finding index using the relative position from the index of the letter 'E'
		 */
		
//		 final int LENGTH_ALPHABET = 26;
//		 double mostFrequent = 0;
//		 int mostFrequentIndex = 0;
//		 final int INDEX_OF_E = 4;
//		
//		 FrequencyAnalyser fA = new FrequencyAnalyser();
//		 fA.setText(ciphertext);
//		 table = fA.analyse();
//		
//		 for (int i = 0; i < LENGTH_ALPHABET; i++) {
//		 if (table.getFrequency(Util.indexToChar(i)) > mostFrequent) {
//		 mostFrequent = table.getFrequency(Util.indexToChar(i));
//		 mostFrequentIndex = i;
//		 }
//		 }
//		 key = Util.mod(mostFrequentIndex - INDEX_OF_E, 26);

		final int LENGTH_ALPHABET = 26;
		double[] chiSqrds = new double[LENGTH_ALPHABET];
		double[] letterProbs = new double[] { 0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
				0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327,
				0.09056, 0.02758, 0.00978, 0.0236, 0.0015, 0.01974, 0.00074 };
		int numberLetters = Util.countLetters(ciphertext);
		double chiSquared;
		double lowestChi;

		FrequencyAnalyser fA = new FrequencyAnalyser();

		//find frequency distribution of letters for each possible key (0-25). Use to find chi squared of each key
		for (int i = 0; i < LENGTH_ALPHABET; i++) {
			
			// start the chi squared statistic as zero
			chiSquared = 0;
			
			// decrypt the ciphertext with current key
			key = i;
			decrypt();
			
			// get frequency analysis table for new plain text
			fA.setText(plaintext);
			table = fA.analyse();
			
			//find sum of Chi Squared statistic for each English letter
			for (int j = 0; j < LENGTH_ALPHABET; j++) {
				chiSquared += Math.pow(
						((table.getFrequency(Util.indexToChar(j)) * numberLetters) - (numberLetters * letterProbs[j])),
						2) / (numberLetters * letterProbs[j]);

			}
			chiSqrds[i] = chiSquared;
		}

		//find which key had lowest chi squared statistic. This is the key.
		lowestChi = chiSqrds[0];
		for (int i = 0; i < LENGTH_ALPHABET; i++) {
			if (lowestChi >= chiSqrds[i]) {
				lowestChi = chiSqrds[i];
				key = i;
			}
		}

	
		// The following code allows you to manually adjust result.
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

		return this.key;
	}

	/**
	 * This method reconstructs the plaintext from the ciphertext with the key.
	 *
	
	 */
	public void decrypt() {

		char temp;
		ciphertext = ciphertext.toUpperCase();
		StringBuilder plaintextSB = new StringBuilder(ciphertext);
		char newChar;

		// go through every character in the cipher text
		for (int i = 0; i < ciphertext.length(); i++) {
			temp = ciphertext.charAt(i);

			// if the character is a letter, change it the new decrypted letter
			if (Util.isValidLetter(temp)) {
				newChar = Util.indexToChar(Util.mod(Util.charToIndex(temp) - key, 26));
				plaintextSB.setCharAt(i, newChar);
			} 

		}
		plaintext = plaintextSB.toString();

	}

	/**
	 * Show the results of the complete analysis.
	 */
	public void showResult() {
		System.out.println("The key is " + this.key);
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
		String mainPath, plaintextFilePath, ciphertextFilePath, plaintext, ciphertext;
		FrequencyAnalyser frequencyAnalyser;
		FrequencyTable frequencyTable;
		FrequencyCryptanalysis cryptanalysis;
		File solutionDirectory;
		String solutionFrequencyFilePath, solutionKeyFilePath, solutionPlaintextFilePath;

		// Add argument -i at run to enable interactive mode (and disable
		// automatic mode)
		if (0 < args.length && args[0].equals("-i")) {
			cryptanalysis = new FrequencyCryptanalysis(INTERACTIVE);
		} else {
			cryptanalysis = new FrequencyCryptanalysis(AUTOMATIC);
		}

		// Get resources
		mainPath = Paths.get(FrequencyCryptanalysis.class.getResource("/").toURI()).toString();
		plaintextFilePath = mainPath + "/res/pg1661.txt";
		ciphertextFilePath = mainPath + "/res/Exercise1Ciphertext.txt";
		solutionDirectory = new File(mainPath + "/solution1");
		solutionFrequencyFilePath = solutionDirectory + "/frequency.txt";
		solutionKeyFilePath = solutionDirectory + "/key.txt";
		solutionPlaintextFilePath = solutionDirectory + "/plaintext.txt";

		// Analyse the readable text
		plaintext = Util.readFileToBuffer(plaintextFilePath);
		frequencyAnalyser = new FrequencyAnalyser();
		frequencyAnalyser.setText(plaintext);
		frequencyTable = frequencyAnalyser.analyse();
		frequencyTable.print();

		// Crack the ciphertext
		ciphertext = Util.readFileToBuffer(ciphertextFilePath);
		cryptanalysis.setCiphertext(ciphertext);
		cryptanalysis.cryptanalysis();
		cryptanalysis.showResult();

		// Write solution in res path
		if (!solutionDirectory.exists()) {
			solutionDirectory.mkdir();
		}
		Util.printBufferToFile(frequencyTable.toString(), solutionFrequencyFilePath);
		Util.printBufferToFile(Integer.toString(cryptanalysis.key), solutionKeyFilePath);
		Util.printBufferToFile(cryptanalysis.plaintext, solutionPlaintextFilePath);
	}
}
