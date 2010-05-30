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
package org.apache.shiro.codec;

/**
 * <a href="http://en.wikipedia.org/wiki/Hexadecimal">Hexadecimal</a> encoder and decoder.
 * <p/>
 * This class was borrowed from Apache Commons Codec SVN repository (rev. {@code 560660}) with modifications
 * to enable Hex conversion without a full dependency on Commons Codec.  We didn't want to reinvent the wheel of
 * great work they've done, but also didn't want to force every Shiro user to depend on the commons-codec.jar
 * <p/>
 * As per the Apache 2.0 license, the original copyright notice and all author and copyright information have
 * remained in tact.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Hexadecimal">Wikipedia: Hexadecimal</a>
 * @since 0.9
 */
public class Hex {

    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /**
     * Encodes the specifed byte array to a character array and then returns that character array
     * as a String.
     *
     * @param bytes the byte array to Hex-encode.
     * @return A String representation of the resultant hex-encoded char array.
     */
    public static String encodeToString(byte[] bytes) {
        char[] encodedChars = encode(bytes);
        return new String(encodedChars);
    }

    /**
     * Converts an array of bytes into an array of characters representing the hexidecimal values of each byte in order.
     * The returned array will be double the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data byte[] to convert to Hex characters
     * @return A char[] containing hexidecimal characters
     */
    public static char[] encode(byte[] data) {

        int l = data.length;

        char[] out = new char[l << 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS[0x0F & data[i]];
        }

        return out;
    }

    /**
     * Converts an array of character bytes representing hexidecimal values into an
     * array of bytes of those same values. The returned array will be half the
     * length of the passed array, as it takes two characters to represent any
     * given byte. An exception is thrown if the passed char array has an odd
     * number of elements.
     *
     * @param array An array of character bytes containing hexidecimal digits
     * @return A byte array containing binary data decoded from
     *         the supplied byte array (representing characters).
     * @throws IllegalArgumentException Thrown if an odd number of characters is supplied
     *                                  to this function
     * @see #decode(char[])
     */
    public static byte[] decode(byte[] array) throws IllegalArgumentException {
        String s = CodecSupport.toString(array);
        return decode(s);
    }

    /**
     * Converts the specified Hex-encoded String into a raw byte array.  This is a
     * convenience method that merely delegates to {@link #decode(char[])} using the
     * argument's hex.toCharArray() value.
     *
     * @param hex a Hex-encoded String.
     * @return A byte array containing binary data decoded from the supplied String's char array.
     */
    public static byte[] decode(String hex) {
        return decode(hex.toCharArray());
    }

    /**
     * Converts an array of characters representing hexidecimal values into an
     * array of bytes of those same values. The returned array will be half the
     * length of the passed array, as it takes two characters to represent any
     * given byte. An exception is thrown if the passed char array has an odd
     * number of elements.
     *
     * @param data An array of characters containing hexidecimal digits
     * @return A byte array containing binary data decoded from
     *         the supplied char array.
     * @throws IllegalArgumentException if an odd number or illegal of characters
     *                                  is supplied
     */
    public static byte[] decode(char[] data) throws IllegalArgumentException {

        int len = data.length;

        if ((len & 0x01) != 0) {
            throw new IllegalArgumentException("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            int f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    /**
     * Converts a hexadecimal character to an integer.
     *
     * @param ch    A character to convert to an integer digit
     * @param index The index of the character in the source
     * @return An integer
     * @throws IllegalArgumentException if ch is an illegal hex character
     */
    protected static int toDigit(char ch, int index) throws IllegalArgumentException {
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new IllegalArgumentException("Illegal hexadecimal charcter " + ch + " at index " + index);
        }
        return digit;
    }


}
