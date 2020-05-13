/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.lang.util;

import java.text.ParseException;
import java.util.*;

/**
 * <p>Simple utility class for String operations useful across the framework.
 * <p/>
 * <p>Some methods in this class were copied from the Spring Framework so we didn't have to re-invent the wheel,
 * and in these cases, we have retained all license, copyright and author information.
 *
 * @since 0.9
 */
public class StringUtils {

    //TODO - complete JavaDoc

    /**
     * Constant representing the empty string, equal to &quot;&quot;
     */
    public static final String EMPTY_STRING = "";

    /**
     * Constant representing the default delimiter character (comma), equal to <code>','</code>
     */
    public static final char DEFAULT_DELIMITER_CHAR = ',';

    /**
     * Constant representing the default quote character (double quote), equal to '&quot;'</code>
     */
    public static final char DEFAULT_QUOTE_CHAR = '"';

    /**
     * Check whether the given String has actual text.
     * More specifically, returns <code>true</code> if the string not <code>null</code>,
     * its length is greater than 0, and it contains at least one non-whitespace character.
     * <p/>
     * <code>StringUtils.hasText(null) == false<br/>
     * StringUtils.hasText("") == false<br/>
     * StringUtils.hasText(" ") == false<br/>
     * StringUtils.hasText("12345") == true<br/>
     * StringUtils.hasText(" 12345 ") == true</code>
     * <p/>
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param str the String to check (may be <code>null</code>)
     * @return <code>true</code> if the String is not <code>null</code>, its length is
     *         greater than 0, and it does not contain whitespace only
     * @see java.lang.Character#isWhitespace
     */
    public static boolean hasText(String str) {
        if (!hasLength(str)) {
            return false;
        }
        int strLen = str.length();
        for (int i = 0; i < strLen; i++) {
            if (!Character.isWhitespace(str.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check that the given String is neither <code>null</code> nor of length 0.
     * Note: Will return <code>true</code> for a String that purely consists of whitespace.
     * <p/>
     * <code>StringUtils.hasLength(null) == false<br/>
     * StringUtils.hasLength("") == false<br/>
     * StringUtils.hasLength(" ") == true<br/>
     * StringUtils.hasLength("Hello") == true</code>
     * <p/>
     * Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param str the String to check (may be <code>null</code>)
     * @return <code>true</code> if the String is not null and has length
     * @see #hasText(String)
     */
    public static boolean hasLength(String str) {
        return (str != null && str.length() > 0);
    }


    /**
     * Test if the given String starts with the specified prefix,
     * ignoring upper/lower case.
     * <p/>
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param str    the String to check
     * @param prefix the prefix to look for
     * @return <code>true</code> starts with the specified prefix (ignoring case), <code>false</code> if it does not.
     * @see java.lang.String#startsWith
     */
    public static boolean startsWithIgnoreCase(String str, String prefix) {
        if (str == null || prefix == null) {
            return false;
        }
        if (str.startsWith(prefix)) {
            return true;
        }
        if (str.length() < prefix.length()) {
            return false;
        }
        String lcStr = str.substring(0, prefix.length()).toLowerCase();
        String lcPrefix = prefix.toLowerCase();
        return lcStr.equals(lcPrefix);
    }

    /**
     * Returns a 'cleaned' representation of the specified argument.  'Cleaned' is defined as the following:
     * <p/>
     * <ol>
     * <li>If the specified <code>String</code> is <code>null</code>, return <code>null</code></li>
     * <li>If not <code>null</code>, {@link String#trim() trim()} it.</li>
     * <li>If the trimmed string is equal to the empty String (i.e. &quot;&quot;), return <code>null</code></li>
     * <li>If the trimmed string is not the empty string, return the trimmed version</li>.
     * </ol>
     * <p/>
     * Therefore this method always ensures that any given string has trimmed text, and if it doesn't, <code>null</code>
     * is returned.
     *
     * @param in the input String to clean.
     * @return a populated-but-trimmed String or <code>null</code> otherwise
     */
    public static String clean(String in) {
        String out = in;

        if (in != null) {
            out = in.trim();
            if (out.equals(EMPTY_STRING)) {
                out = null;
            }
        }

        return out;
    }

    /**
     * Returns the specified array as a comma-delimited (',') string.
     *
     * @param array the array whose contents will be converted to a string.
     * @return the array's contents as a comma-delimited (',') string.
     * @since 1.0
     */
    public static String toString(Object[] array) {
        return toDelimitedString(array, ",");
    }

    /**
     * Returns the array's contents as a string, with each element delimited by the specified
     * {@code delimiter} argument.  Useful for {@code toString()} implementations and log messages.
     *
     * @param array     the array whose contents will be converted to a string
     * @param delimiter the delimiter to use between each element
     * @return a single string, delimited by the specified {@code delimiter}.
     * @since 1.0
     */
    public static String toDelimitedString(Object[] array, String delimiter) {
        if (array == null || array.length == 0) {
            return EMPTY_STRING;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < array.length; i++) {
            if (i > 0) {
                sb.append(delimiter);
            }
            sb.append(array[i]);
        }
        return sb.toString();
    }

    /**
     * Returns the collection's contents as a string, with each element delimited by the specified
     * {@code delimiter} argument.  Useful for {@code toString()} implementations and log messages.
     *
     * @param c         the collection whose contents will be converted to a string
     * @param delimiter the delimiter to use between each element
     * @return a single string, delimited by the specified {@code delimiter}.
     * @since 1.2
     */
    public static String toDelimitedString(Collection c, String delimiter) {
        if (c == null || c.isEmpty()) {
            return EMPTY_STRING;
        }
        return join(c.iterator(), delimiter);
    }

    /**
     * Tokenize the given String into a String array via a StringTokenizer.
     * Trims tokens and omits empty tokens.
     * <p>The given delimiters string is supposed to consist of any number of
     * delimiter characters. Each of those characters can be used to separate
     * tokens. A delimiter is always a single character; for multi-character
     * delimiters, consider using <code>delimitedListToStringArray</code>
     * <p/>
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param str        the String to tokenize
     * @param delimiters the delimiter characters, assembled as String
     *                   (each of those characters is individually considered as delimiter).
     * @return an array of the tokens
     * @see java.util.StringTokenizer
     * @see java.lang.String#trim()
     */
    public static String[] tokenizeToStringArray(String str, String delimiters) {
        return tokenizeToStringArray(str, delimiters, true, true);
    }

    /**
     * Tokenize the given String into a String array via a StringTokenizer.
     * <p>The given delimiters string is supposed to consist of any number of
     * delimiter characters. Each of those characters can be used to separate
     * tokens. A delimiter is always a single character; for multi-character
     * delimiters, consider using <code>delimitedListToStringArray</code>
     * <p/>
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param str               the String to tokenize
     * @param delimiters        the delimiter characters, assembled as String
     *                          (each of those characters is individually considered as delimiter)
     * @param trimTokens        trim the tokens via String's <code>trim</code>
     * @param ignoreEmptyTokens omit empty tokens from the result array
     *                          (only applies to tokens that are empty after trimming; StringTokenizer
     *                          will not consider subsequent delimiters as token in the first place).
     * @return an array of the tokens (<code>null</code> if the input String
     *         was <code>null</code>)
     * @see java.util.StringTokenizer
     * @see java.lang.String#trim()
     */
    @SuppressWarnings({"unchecked"})
    public static String[] tokenizeToStringArray(
            String str, String delimiters, boolean trimTokens, boolean ignoreEmptyTokens) {

        if (str == null) {
            return null;
        }
        StringTokenizer st = new StringTokenizer(str, delimiters);
        List tokens = new ArrayList();
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            if (trimTokens) {
                token = token.trim();
            }
            if (!ignoreEmptyTokens || token.length() > 0) {
                tokens.add(token);
            }
        }
        return toStringArray(tokens);
    }

    /**
     * Copy the given Collection into a String array.
     * The Collection must contain String elements only.
     * <p/>
     * <p>Copied from the Spring Framework while retaining all license, copyright and author information.
     *
     * @param collection the Collection to copy
     * @return the String array (<code>null</code> if the passed-in
     *         Collection was <code>null</code>)
     */
    @SuppressWarnings({"unchecked"})
    public static String[] toStringArray(Collection collection) {
        if (collection == null) {
            return null;
        }
        return (String[]) collection.toArray(new String[collection.size()]);
    }

    public static String[] splitKeyValue(String aLine) throws ParseException {
        String line = clean(aLine);
        if (line == null) {
            return null;
        }
        String[] split = line.split(" ", 2);
        if (split.length != 2) {
            //fallback to checking for an equals sign
            split = line.split("=", 2);
            if (split.length != 2) {
                String msg = "Unable to determine Key/Value pair from line [" + line + "].  There is no space from " +
                        "which the split location could be determined.";
                throw new ParseException(msg, 0);
            }

        }

        split[0] = clean(split[0]);
        split[1] = clean(split[1]);
        if (split[1].startsWith("=")) {
            //they used spaces followed by an equals followed by zero or more spaces to split the key/value pair, so
            //remove the equals sign to result in only the key and values in the
            split[1] = clean(split[1].substring(1));
        }

        if (split[0] == null) {
            String msg = "No valid key could be found in line [" + line + "] to form a key/value pair.";
            throw new ParseException(msg, 0);
        }
        if (split[1] == null) {
            String msg = "No corresponding value could be found in line [" + line + "] for key [" + split[0] + "]";
            throw new ParseException(msg, 0);
        }

        return split;
    }

    public static String[] split(String line) {
        return split(line, DEFAULT_DELIMITER_CHAR);
    }

    public static String[] split(String line, char delimiter) {
        return split(line, delimiter, DEFAULT_QUOTE_CHAR);
    }

    public static String[] split(String line, char delimiter, char quoteChar) {
        return split(line, delimiter, quoteChar, quoteChar);
    }

    public static String[] split(String line, char delimiter, char beginQuoteChar, char endQuoteChar) {
        return split(line, delimiter, beginQuoteChar, endQuoteChar, false, true);
    }

    /**
     * Splits the specified delimited String into tokens, supporting quoted tokens so that quoted strings themselves
     * won't be tokenized.
     * <p/>
     * This method's implementation is very loosely based (with significant modifications) on
     * <a href="http://blogs.bytecode.com.au/glen">Glen Smith</a>'s open-source
     * <a href="http://opencsv.svn.sourceforge.net/viewvc/opencsv/trunk/src/au/com/bytecode/opencsv/CSVReader.java?&view=markup">CSVReader.java</a>
     * file.
     * <p/>
     * That file is Apache 2.0 licensed as well, making Glen's code a great starting point for us to modify to
     * our needs.
     *
     * @param aLine          the String to parse
     * @param delimiter      the delimiter by which the <tt>line</tt> argument is to be split
     * @param beginQuoteChar the character signifying the start of quoted text (so the quoted text will not be split)
     * @param endQuoteChar   the character signifying the end of quoted text
     * @param retainQuotes   if the quotes themselves should be retained when constructing the corresponding token
     * @param trimTokens     if leading and trailing whitespace should be trimmed from discovered tokens.
     * @return the tokens discovered from parsing the given delimited <tt>line</tt>.
     */
    public static String[] split(String aLine, char delimiter, char beginQuoteChar, char endQuoteChar,
                                 boolean retainQuotes, boolean trimTokens) {
        String line = clean(aLine);
        if (line == null) {
            return null;
        }

        List<String> tokens = new ArrayList<String>();
        StringBuilder sb = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {

            char c = line.charAt(i);
            if (c == beginQuoteChar) {
                // this gets complex... the quote may end a quoted block, or escape another quote.
                // do a 1-char lookahead:
                if (inQuotes  // we are in quotes, therefore there can be escaped quotes in here.
                        && line.length() > (i + 1)  // there is indeed another character to check.
                        && line.charAt(i + 1) == beginQuoteChar) { // ..and that char. is a quote also.
                    // we have two quote chars in a row == one quote char, so consume them both and
                    // put one on the token. we do *not* exit the quoted text.
                    sb.append(line.charAt(i + 1));
                    i++;
                } else {
                    inQuotes = !inQuotes;
                    if (retainQuotes) {
                        sb.append(c);
                    }
                }
            } else if (c == endQuoteChar) {
                inQuotes = !inQuotes;
                if (retainQuotes) {
                    sb.append(c);
                }
            } else if (c == delimiter && !inQuotes) {
                String s = sb.toString();
                if (trimTokens) {
                    s = s.trim();
                }
                tokens.add(s);
                sb = new StringBuilder(); // start work on next token
            } else {
                sb.append(c);
            }
        }
        String s = sb.toString();
        if (trimTokens) {
            s = s.trim();
        }
        tokens.add(s);
        return tokens.toArray(new String[tokens.size()]);
    }

    /**
     * Joins the elements of the provided {@code Iterator} into
     * a single String containing the provided elements.</p>
     * <p/>
     * No delimiter is added before or after the list.
     * A {@code null} separator is the same as an empty String ("").</p>
     * <p/>
     * Copied from Commons Lang, version 3 (r1138702).</p>
     *
     * @param iterator  the {@code Iterator} of values to join together, may be null
     * @param separator the separator character to use, null treated as ""
     * @return the joined String, {@code null} if null iterator input
     * @since 1.2
     */
    public static String join(Iterator<?> iterator, String separator) {
        final String empty = "";

        // handle null, zero and one elements before building a buffer
        if (iterator == null) {
            return null;
        }
        if (!iterator.hasNext()) {
            return empty;
        }
        Object first = iterator.next();
        if (!iterator.hasNext()) {
            return first == null ? empty : first.toString();
        }

        // two or more elements
        StringBuilder buf = new StringBuilder(256); // Java default is 16, probably too small
        if (first != null) {
            buf.append(first);
        }

        while (iterator.hasNext()) {
            if (separator != null) {
                buf.append(separator);
            }
            Object obj = iterator.next();
            if (obj != null) {
                buf.append(obj);
            }
        }
        return buf.toString();
    }

    /**
     * Splits the {@code delimited} string (delimited by the specified {@code separator} character) and returns the
     * delimited values as a {@code Set}.
     * <p/>
     * If either argument is {@code null}, this method returns {@code null}.
     *
     * @param delimited the string to split
     * @param separator the character that delineates individual tokens to split
     * @return the delimited values as a {@code Set}.
     * @since 1.2
     */
    public static Set<String> splitToSet(String delimited, String separator) {
        if (delimited == null || separator == null) {
            return null;
        }
        String[] split = split(delimited, separator.charAt(0));
        return asSet(split);
    }

    /**
     * Returns the input argument, but ensures the first character is capitalized (if possible).
     * @param in the string to uppercase the first character.
     * @return the input argument, but with the first character capitalized (if possible).
     * @since 1.2
     */
    public static String uppercaseFirstChar(String in) {
        if (in == null || in.length() == 0) {
            return in;
        }
        int length = in.length();
        StringBuilder sb = new StringBuilder(length);

        sb.append(Character.toUpperCase(in.charAt(0)));
        if (length > 1) {
            String remaining = in.substring(1);
            sb.append(remaining);
        }
        return sb.toString();
    }

    //////////////////////////
    // From CollectionUtils //
    //////////////////////////
    // CollectionUtils cannot be removed from shiro-core until 2.0 as it has a dependency on PrincipalCollection


    private static <E> Set<E> asSet(E... elements) {
        if (elements == null || elements.length == 0) {
            return Collections.emptySet();
        }

        if (elements.length == 1) {
            return Collections.singleton(elements[0]);
        }

        LinkedHashSet<E> set = new LinkedHashSet<E>(elements.length * 4 / 3 + 1);
        Collections.addAll(set, elements);
        return set;
    }

}
