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
package org.apache.shiro.lang.codec;

import org.apache.shiro.lang.util.ByteSource;

import java.io.*;

/**
 * Base abstract class that provides useful encoding and decoding operations, especially for character data.
 *
 * @since 0.9
 */
public abstract class CodecSupport {

    /**
     * Shiro's default preferred character encoding, equal to <b><code>UTF-8</code></b>.
     */
    public static final String PREFERRED_ENCODING = "UTF-8";

    /**
     * Converts the specified character array to a byte array using the Shiro's preferred encoding (UTF-8).
     * <p/>
     * This is a convenience method equivalent to calling the {@link #toBytes(String,String)} method with a
     * a wrapping String and {@link CodecSupport#PREFERRED_ENCODING PREFERRED_ENCODING}, i.e.
     * <p/>
     * <code>toBytes( new String(chars), {@link CodecSupport#PREFERRED_ENCODING PREFERRED_ENCODING} );</code>
     *
     * @param chars the character array to be converted to a byte array.
     * @return the byte array of the UTF-8 encoded character array.
     */
    public static byte[] toBytes(char[] chars) {
        return toBytes(new String(chars), PREFERRED_ENCODING);
    }

    /**
     * Converts the specified character array into a byte array using the specified character encoding.
     * <p/>
     * This is a convenience method equivalent to calling the {@link #toBytes(String,String)} method with a
     * a wrapping String and the specified encoding, i.e.
     * <p/>
     * <code>toBytes( new String(chars), encoding );</code>
     *
     * @param chars    the character array to be converted to a byte array
     * @param encoding the character encoding to use to when converting to bytes.
     * @return the bytes of the specified character array under the specified encoding.
     * @throws CodecException if the JVM does not support the specified encoding.
     */
    public static byte[] toBytes(char[] chars, String encoding) throws CodecException {
        return toBytes(new String(chars), encoding);
    }

    /**
     * Converts the specified source argument to a byte array with Shiro's
     * {@link CodecSupport#PREFERRED_ENCODING PREFERRED_ENCODING}.
     *
     * @param source the string to convert to a byte array.
     * @return the bytes representing the specified string under the {@link CodecSupport#PREFERRED_ENCODING PREFERRED_ENCODING}.
     * @see #toBytes(String, String)
     */
    public static byte[] toBytes(String source) {
        return toBytes(source, PREFERRED_ENCODING);
    }

    /**
     * Converts the specified source to a byte array via the specified encoding, throwing a
     * {@link CodecException CodecException} if the encoding fails.
     *
     * @param source   the source string to convert to a byte array.
     * @param encoding the encoding to use to use.
     * @return the byte array of the specified source with the given encoding.
     * @throws CodecException if the JVM does not support the specified encoding.
     */
    public static byte[] toBytes(String source, String encoding) throws CodecException {
        try {
            return source.getBytes(encoding);
        } catch (UnsupportedEncodingException e) {
            String msg = "Unable to convert source [" + source + "] to byte array using " +
                    "encoding '" + encoding + "'";
            throw new CodecException(msg, e);
        }
    }

    /**
     * Converts the specified byte array to a String using the {@link CodecSupport#PREFERRED_ENCODING PREFERRED_ENCODING}.
     *
     * @param bytes the byte array to turn into a String.
     * @return the specified byte array as an encoded String ({@link CodecSupport#PREFERRED_ENCODING PREFERRED_ENCODING}).
     * @see #toString(byte[], String)
     */
    public static String toString(byte[] bytes) {
        return toString(bytes, PREFERRED_ENCODING);
    }

    /**
     * Converts the specified byte array to a String using the specified character encoding.  This implementation
     * does the same thing as <code>new {@link String#String(byte[], String) String(byte[], encoding)}</code>, but will
     * wrap any {@link UnsupportedEncodingException} with a nicer runtime {@link CodecException}, allowing you to
     * decide whether or not you want to catch the exception or let it propagate.
     *
     * @param bytes    the byte array to convert to a String
     * @param encoding the character encoding used to encode the String.
     * @return the specified byte array as an encoded String
     * @throws CodecException if the JVM does not support the specified encoding.
     */
    public static String toString(byte[] bytes, String encoding) throws CodecException {
        try {
            return new String(bytes, encoding);
        } catch (UnsupportedEncodingException e) {
            String msg = "Unable to convert byte array to String with encoding '" + encoding + "'.";
            throw new CodecException(msg, e);
        }
    }

    /**
     * Returns the specified byte array as a character array using the
     * {@link CodecSupport#PREFERRED_ENCODING PREFERRED_ENCODING}.
     *
     * @param bytes the byte array to convert to a char array
     * @return the specified byte array encoded as a character array ({@link CodecSupport#PREFERRED_ENCODING PREFERRED_ENCODING}).
     * @see #toChars(byte[], String)
     */
    public static char[] toChars(byte[] bytes) {
        return toChars(bytes, PREFERRED_ENCODING);
    }

    /**
     * Converts the specified byte array to a character array using the specified character encoding.
     * <p/>
     * Effectively calls <code>{@link #toString(byte[], String) toString(bytes,encoding)}.{@link String#toCharArray() toCharArray()};</code>
     *
     * @param bytes    the byte array to convert to a String
     * @param encoding the character encoding used to encode the bytes.
     * @return the specified byte array as an encoded char array
     * @throws CodecException if the JVM does not support the specified encoding.
     */
    public static char[] toChars(byte[] bytes, String encoding) throws CodecException {
        return toString(bytes, encoding).toCharArray();
    }

    /**
     * Returns {@code true} if the specified object can be easily converted to bytes by instances of this class,
     * {@code false} otherwise.
     * <p/>
     * The default implementation returns {@code true} IFF the specified object is an instance of one of the following
     * types:
     * <ul>
     * <li>{@code byte[]}</li>
     * <li>{@code char[]}</li>
     * <li>{@link ByteSource}</li>
     * <li>{@link String}</li>
     * <li>{@link File}</li>
     * </li>{@link InputStream}</li>
     * </ul>
     *
     * @param o the object to test to see if it can be easily converted to a byte array
     * @return {@code true} if the specified object can be easily converted to bytes by instances of this class,
     *         {@code false} otherwise.
     * @since 1.0
     */
    protected boolean isByteSource(Object o) {
        return o instanceof byte[] || o instanceof char[] || o instanceof String ||
                o instanceof ByteSource || o instanceof File || o instanceof InputStream;
    }

    /**
     * Converts the specified Object into a byte array.
     * <p/>
     * If the argument is a {@code byte[]}, {@code char[]}, {@link ByteSource}, {@link String}, {@link File}, or
     * {@link InputStream}, it will be converted automatically and returned.}
     * <p/>
     * If the argument is anything other than these types, it is passed to the
     * {@link #objectToBytes(Object) objectToBytes} method which must be overridden by subclasses.
     *
     * @param o the Object to convert into a byte array
     * @return a byte array representation of the Object argument.
     */
    protected byte[] toBytes(Object o) {
        if (o == null) {
            String msg = "Argument for byte conversion cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        if (o instanceof byte[]) {
            return (byte[]) o;
        } else if (o instanceof ByteSource) {
            return ((ByteSource) o).getBytes();
        } else if (o instanceof char[]) {
            return toBytes((char[]) o);
        } else if (o instanceof String) {
            return toBytes((String) o);
        } else if (o instanceof File) {
            return toBytes((File) o);
        } else if (o instanceof InputStream) {
            return toBytes((InputStream) o);
        } else {
            return objectToBytes(o);
        }
    }

    /**
     * Converts the specified Object into a String.
     * <p/>
     * If the argument is a {@code byte[]} or {@code char[]} it will be converted to a String using the
     * {@link #PREFERRED_ENCODING}.  If a String, it will be returned as is.
     * <p/>
     * If the argument is anything other than these three types, it is passed to the
     * {@link #objectToString(Object) objectToString} method.
     *
     * @param o the Object to convert into a byte array
     * @return a byte array representation of the Object argument.
     */
    protected String toString(Object o) {
        if (o == null) {
            String msg = "Argument for String conversion cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        if (o instanceof byte[]) {
            return toString((byte[]) o);
        } else if (o instanceof char[]) {
            return new String((char[]) o);
        } else if (o instanceof String) {
            return (String) o;
        } else {
            return objectToString(o);
        }
    }

    protected byte[] toBytes(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File argument cannot be null.");
        }
        try {
            return toBytes(new FileInputStream(file));
        } catch (FileNotFoundException e) {
            String msg = "Unable to acquire InputStream for file [" + file + "]";
            throw new CodecException(msg, e);
        }
    }

    /**
     * Converts the specified {@link InputStream InputStream} into a byte array.
     *
     * @param in the InputStream to convert to a byte array
     * @return the bytes of the input stream
     * @throws IllegalArgumentException if the {@code InputStream} argument is {@code null}.
     * @throws CodecException           if there is any problem reading from the {@link InputStream}.
     * @since 1.0
     */
    protected byte[] toBytes(InputStream in) {
        if (in == null) {
            throw new IllegalArgumentException("InputStream argument cannot be null.");
        }
        final int BUFFER_SIZE = 512;
        ByteArrayOutputStream out = new ByteArrayOutputStream(BUFFER_SIZE);
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead;
        try {
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            return out.toByteArray();
        } catch (IOException ioe) {
            throw new CodecException(ioe);
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
            }
            try {
                out.close();
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Default implementation throws a CodecException immediately since it can't infer how to convert the Object
     * to a byte array.  This method must be overridden by subclasses if anything other than the three default
     * types (listed in the {@link #toBytes(Object) toBytes(Object)} JavaDoc) are to be converted to a byte array.
     *
     * @param o the Object to convert to a byte array.
     * @return a byte array representation of the Object argument.
     */
    protected byte[] objectToBytes(Object o) {
        String msg = "The " + getClass().getName() + " implementation only supports conversion to " +
                "byte[] if the source is of type byte[], char[], String, " + ByteSource.class.getName() +
                " File or InputStream.  The instance provided as a method " +
                "argument is of type [" + o.getClass().getName() + "].  If you would like to convert " +
                "this argument type to a byte[], you can 1) convert the argument to one of the supported types " +
                "yourself and then use that as the method argument or 2) subclass " + getClass().getName() +
                "and override the objectToBytes(Object o) method.";
        throw new CodecException(msg);
    }

    /**
     * Default implementation merely returns <code>objectArgument.toString()</code>.  Subclasses can override this
     * method for different mechanisms of converting an object to a String.
     *
     * @param o the Object to convert to a byte array.
     * @return a String representation of the Object argument.
     */
    protected String objectToString(Object o) {
        return o.toString();
    }
}
