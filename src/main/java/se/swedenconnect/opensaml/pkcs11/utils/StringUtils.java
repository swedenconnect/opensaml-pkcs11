package se.swedenconnect.opensaml.pkcs11.utils;

/**
 * This class performs some simple String functions normally provided by the Spring framework
 */
public class StringUtils {
    /**
     * Test if a String has a value and is not null
     *
     * @param text String to be tested
     * @return true if the string is not null and not empty or just white space.
     */
    public static boolean hasText(String text) {
        return text != null && !text.trim().isEmpty();
    }

    /**
     * Returns the trimmed string if present
     *
     * @param text Text to trim
     * @return The trimmed string or null if empty
     */
    public static String getTrimmedIfNotNull(String text) {
        return hasText(text) ? text.trim() : null;
    }


}
