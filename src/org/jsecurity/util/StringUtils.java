/*
 * Copyright 2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */
package org.jsecurity.util;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class StringUtils {

    public static final char DEFAULT_DELIMITER_CHAR = ',';
    public static final char DEFAULT_QUOTE_CHAR = '"';

    public static String[] split(String line) {
        return split(line, DEFAULT_DELIMITER_CHAR );
    }

    public static String[] split(String line, char delimiter ) {
        return split(line, delimiter, DEFAULT_QUOTE_CHAR );
    }

    public static String[] split(String line, char delimiter, char quoteChar ) {
        return split(line, delimiter, quoteChar, quoteChar );
    }

    public static String[] split(String line, char delimiter, char beginQuoteChar, char endQuoteChar ) {
        return split(line, delimiter, beginQuoteChar, endQuoteChar, false, true );
    }

    public static String[] split(String line, char delimiter, char beginQuoteChar, char endQuoteChar, boolean retainQuotes, boolean trimTokens ) {
        if (line == null) {
            return null;
        }

        List<String> tokens = new ArrayList<String>();
        StringBuffer sb = new StringBuffer();
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
                    if ( retainQuotes ) {
                        sb.append(c);
                    }
                }
            } else if ( c == endQuoteChar ) {
                inQuotes = !inQuotes;
                if ( retainQuotes ) {
                    sb.append(c);
                }
            } else if (c == delimiter && !inQuotes) {
                String s = sb.toString();
                if ( trimTokens ) {
                    s = s.trim();
                }
                tokens.add(s);
                sb = new StringBuffer(); // start work on next token
            } else {
                sb.append(c);
            }
        }
        String s = sb.toString();
        if ( trimTokens ) {
            s = s.trim();
        }
        tokens.add(s);
        return tokens.toArray(new String[tokens.size()]);
    }

}
