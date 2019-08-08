package uk.ac.ncl.undergraduate.modules.csc3621.cryptanalysis.easyfreq;

import java.util.HashMap;
import java.util.Map;

/**
 * This class is to compute a frequency table of a texts.
 *
 * @author Changyu Dong
 * @author Roberto Metere
 * @author Dalton Yates
 */
public class FrequencyAnalyser {

    /**
     * The text to analyse
     */
    private String text;

    /**
     * Get the text to analyse.
     *
     * @return the text to analyse.
     */
    public String getText() {
        return text;
    }

    /**
     * Set the text to analyse.
     *
     * @param text the text to analyse.
     */
    public void setText(String text) {
        this.text = text;
    }

    /**
     * This method returns a frequency table as a result of the analysis of the
     * text.
     *
     *
     * @return frequency table as a result of the analysis of the text
     */
    public FrequencyTable analyse() {

    	//iniitalise variables
    	final int LENGTH_ALPHABET = 26;
    	FrequencyTable currentFT = new FrequencyTable();
    	int allLettersCount = 0;
    	String upperCaseText = getText().toUpperCase();
    	double freq;
    	Map <Character, Integer> countMap = new HashMap<Character, Integer>();
    	
    	//counts number of letters in text
    	allLettersCount = Util.countLetters(upperCaseText);
    	
    	// initialises hash map
    	for (int i = 0; i < LENGTH_ALPHABET; i++){
    		countMap.put(Util.indexToChar(i), 0);
    	}
    	
    	
    	//populates hash map with the how many times each letter has occurred
    	for (int i = 0; i < text.length(); i++){
    		 char currentLetter = upperCaseText.charAt(i);
    		 if(countMap.containsKey(currentLetter)){
    			 countMap.put(currentLetter, countMap.get(currentLetter) + 1);
    		 }
    	}
    	
    	//populates frequency table
    	for (int i = 0; i < LENGTH_ALPHABET; i++){
    		freq = (double) countMap.get(Util.indexToChar(i)) / (double) allLettersCount;
    		currentFT.setFrequency(Util.indexToChar(i), freq);
    	}
    	
    	return currentFT;


    }


}
