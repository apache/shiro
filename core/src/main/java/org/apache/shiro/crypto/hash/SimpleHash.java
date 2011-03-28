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
package org.apache.shiro.crypto.hash;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecException;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.UnknownAlgorithmException;
import org.apache.shiro.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * A {@code Hash} implementation that allows any {@link java.security.MessageDigest MessageDigest} algorithm name to
 * be used.  This class is a less type-safe variant than the other {@code AbstractHash} subclasses
 * (e.g. {@link Sha512Hash}, etc), but it does allow for any algorithm name to be specified in case the other subclass
 * implementations do not represent an algorithm that you may want to use.
 * <p/>
 * As of Shiro 1.1, this class effectively replaces the (now-deprecated) {@link AbstractHash} class.  It subclasses
 * {@code AbstractHash} only to retain backwards-compatibility.
 *
 * @since 1.1
 */
public class SimpleHash extends AbstractHash {

    /**
     * The {@link java.security.MessageDigest MessageDigest} algorithm name to use when performing the hash.
     */
    private final String algorithmName;

    /**
     * The hashed data
     */
    private byte[] bytes = null;

    /**
     * Cached value of the {@link #toHex() toHex()} call so multiple calls won't incur repeated overhead.
     */
    private transient String hexEncoded = null;

    /**
     * Cached value of the {@link #toBase64() toBase64()} call so multiple calls won't incur repeated overhead.
     */
    private transient String base64Encoded = null;

    /**
     * Creates an new instance with only its {@code algorithmName} set - no hashing is performed.
     * <p/>
     * Because all other constructors in this class hash the {@code source} constructor argument, this
     * constructor is useful in scenarios when you have a byte array that you know is already hashed and
     * just want to set the bytes in their raw form directly on an instance.  After using this constructor,
     * you can then immediately call {@link #setBytes setBytes} to have a fully-initialized instance.
     * <p/>
     * <b>N.B.</b>The algorithm identified by the {@code algorithmName} parameter must be available on the JVM.  If it
     * is not, a {@link UnknownAlgorithmException} will be thrown when the hash is performed (not at instantiation).
     *
     * @param algorithmName the {@link java.security.MessageDigest MessageDigest} algorithm name to use when
     *                      performing the hash.
     * @see UnknownAlgorithmException
     */
    public SimpleHash(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Creates an {@code algorithmName}-specific hash of the specified {@code source} with no {@code salt} using a
     * single hash iteration.
     * <p/>
     * This is a convenience constructor that merely executes <code>this( algorithmName, source, null, 1);</code>.
     * <p/>
     * Please see the
     * {@link #SimpleHash(String algorithmName, Object source, Object salt, int numIterations) SimpleHashHash(algorithmName, Object,Object,int)}
     * constructor for the types of Objects that may be passed into this constructor, as well as how to support further
     * types.
     *
     * @param algorithmName the {@link java.security.MessageDigest MessageDigest} algorithm name to use when
     *                      performing the hash.
     * @param source        the object to be hashed.
     * @throws org.apache.shiro.codec.CodecException
     *                                   if the specified {@code source} cannot be converted into a byte array (byte[]).
     * @throws UnknownAlgorithmException if the {@code algorithmName} is not available.
     */
    public SimpleHash(String algorithmName, Object source) throws CodecException, UnknownAlgorithmException {
        this(algorithmName, source, null, 1);
    }

    /**
     * Creates an {@code algorithmName}-specific hash of the specified {@code source} using the given {@code salt}
     * using a single hash iteration.
     * <p/>
     * It is a convenience constructor that merely executes <code>this( algorithmName, source, salt, 1);</code>.
     * <p/>
     * Please see the
     * {@link #SimpleHash(String algorithmName, Object source, Object salt, int numIterations) SimpleHashHash(algorithmName, Object,Object,int)}
     * constructor for the types of Objects that may be passed into this constructor, as well as how to support further
     * types.
     *
     * @param algorithmName the {@link java.security.MessageDigest MessageDigest} algorithm name to use when
     *                      performing the hash.
     * @param source        the source object to be hashed.
     * @param salt          the salt to use for the hash
     * @throws CodecException            if either constructor argument cannot be converted into a byte array.
     * @throws UnknownAlgorithmException if the {@code algorithmName} is not available.
     */
    public SimpleHash(String algorithmName, Object source, Object salt) throws CodecException, UnknownAlgorithmException {
        this(algorithmName, source, salt, 1);
    }

    /**
     * Creates an {@code algorithmName}-specific hash of the specified {@code source} using the given
     * {@code salt} a total of {@code hashIterations} times.
     * <p/>
     * By default, this class only supports Object method arguments of
     * type {@code byte[]}, {@code char[]}, {@link String}, {@link java.io.File File},
     * {@link java.io.InputStream InputStream} or {@link org.apache.shiro.util.ByteSource ByteSource}.  If either
     * argument is anything other than these types a {@link org.apache.shiro.codec.CodecException CodecException}
     * will be thrown.
     * <p/>
     * If you want to be able to hash other object types, or use other salt types, you need to override the
     * {@link #toBytes(Object) toBytes(Object)} method to support those specific types.  Your other option is to
     * convert your arguments to one of the default supported types first before passing them in to this
     * constructor}.
     *
     * @param algorithmName  the {@link java.security.MessageDigest MessageDigest} algorithm name to use when
     *                       performing the hash.
     * @param source         the source object to be hashed.
     * @param salt           the salt to use for the hash
     * @param hashIterations the number of times the {@code source} argument hashed for attack resiliency.
     * @throws CodecException            if either Object constructor argument cannot be converted into a byte array.
     * @throws UnknownAlgorithmException if the {@code algorithmName} is not available.
     */
    public SimpleHash(String algorithmName, Object source, Object salt, int hashIterations)
            throws CodecException, UnknownAlgorithmException {
        if (!StringUtils.hasText(algorithmName)) {
            throw new NullPointerException("algorithmName argument cannot be null or empty.");
        }
        this.algorithmName = algorithmName;
        hash(source, salt, hashIterations);
    }

    private void hash(Object source, Object salt, int hashIterations) throws CodecException, UnknownAlgorithmException {
        byte[] sourceBytes = toBytes(source);
        byte[] saltBytes = null;
        if (salt != null) {
            saltBytes = toBytes(salt);
        }
        byte[] hashedBytes = hash(sourceBytes, saltBytes, hashIterations);
        setBytes(hashedBytes);
    }

    /**
     * Returns the {@link java.security.MessageDigest MessageDigest} algorithm name to use when performing the hash.
     *
     * @return the {@link java.security.MessageDigest MessageDigest} algorithm name to use when performing the hash.
     */
    public String getAlgorithmName() {
        return this.algorithmName;
    }

    public byte[] getBytes() {
        return this.bytes;
    }

    /**
     * Sets the raw bytes stored by this hash instance.
     * <p/>
     * The bytes are kept in raw form - they will not be hashed/changed.  This is primarily a utility method for
     * constructing a Hash instance when the hashed value is already known.
     *
     * @param alreadyHashedBytes the raw already-hashed bytes to store in this instance.
     */
    public void setBytes(byte[] alreadyHashedBytes) {
        this.bytes = alreadyHashedBytes;
        this.hexEncoded = null;
        this.base64Encoded = null;
    }

    /**
     * Returns the JDK MessageDigest instance to use for executing the hash.
     *
     * @param algorithmName the algorithm to use for the hash, provided by subclasses.
     * @return the MessageDigest object for the specified {@code algorithm}.
     * @throws UnknownAlgorithmException if the specified algorithm name is not available.
     */
    protected MessageDigest getDigest(String algorithmName) throws UnknownAlgorithmException {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "No native '" + algorithmName + "' MessageDigest instance available on the current JVM.";
            throw new UnknownAlgorithmException(msg, e);
        }
    }

    /**
     * Hashes the specified byte array without a salt for a single iteration.
     *
     * @param bytes the bytes to hash.
     * @return the hashed bytes.
     * @throws UnknownAlgorithmException if the configured {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes) throws UnknownAlgorithmException {
        return hash(bytes, null, 1);
    }

    /**
     * Hashes the specified byte array using the given {@code salt} for a single iteration.
     *
     * @param bytes the bytes to hash
     * @param salt  the salt to use for the initial hash
     * @return the hashed bytes
     * @throws UnknownAlgorithmException if the configured {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes, byte[] salt) throws UnknownAlgorithmException {
        return hash(bytes, salt, 1);
    }

    /**
     * Hashes the specified byte array using the given {@code salt} for the specified number of iterations.
     *
     * @param bytes          the bytes to hash
     * @param salt           the salt to use for the initial hash
     * @param hashIterations the number of times the the {@code bytes} will be hashed (for attack resiliency).
     * @return the hashed bytes.
     * @throws UnknownAlgorithmException if the {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) throws UnknownAlgorithmException {
        MessageDigest digest = getDigest(getAlgorithmName());
        if (salt != null) {
            digest.reset();
            digest.update(salt);
        }
        byte[] hashed = digest.digest(bytes);
        int iterations = hashIterations - 1; //already hashed once above
        //iterate remaining number:
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return hashed;
    }

    /**
     * Returns a hex-encoded string of the underlying {@link #getBytes byte array}.
     * <p/>
     * This implementation caches the resulting hex string so multiple calls to this method remain efficient.
     * However, calling {@link #setBytes setBytes} will null the cached value, forcing it to be recalculated the
     * next time this method is called.
     *
     * @return a hex-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toHex() {
        if (this.hexEncoded == null) {
            this.hexEncoded = Hex.encodeToString(getBytes());
        }
        return this.hexEncoded;
    }

    /**
     * Returns a Base64-encoded string of the underlying {@link #getBytes byte array}.
     * <p/>
     * This implementation caches the resulting Base64 string so multiple calls to this method remain efficient.
     * However, calling {@link #setBytes setBytes} will null the cached value, forcing it to be recalculated the
     * next time this method is called.
     *
     * @return a Base64-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toBase64() {
        if (this.base64Encoded == null) {
            //cache result in case this method is called multiple times.
            this.base64Encoded = Base64.encodeToString(getBytes());
        }
        return this.base64Encoded;
    }

    /**
     * Simple implementation that merely returns {@link #toHex() toHex()}.
     *
     * @return the {@link #toHex() toHex()} value.
     */
    public String toString() {
        return toHex();
    }

    /**
     * Returns {@code true} if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * this Hash's byte array, {@code false} otherwise.
     *
     * @param o the object (Hash) to check for equality.
     * @return {@code true} if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     *         this Hash's byte array, {@code false} otherwise.
     */
    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash) o;
            return Arrays.equals(getBytes(), other.getBytes());
        }
        return false;
    }

    /**
     * Simply returns toHex().hashCode();
     *
     * @return toHex().hashCode()
     */
    public int hashCode() {
        return toHex().hashCode();
    }

    private static void printMainUsage(Class<? extends AbstractHash> clazz, String type) {
        System.out.println("Prints an " + type + " hash value.");
        System.out.println("Usage: java " + clazz.getName() + " [-base64] [-salt <saltValue>] [-times <N>] <valueToHash>");
        System.out.println("Options:");
        System.out.println("\t-base64\t\tPrints the hash value as a base64 String instead of the default hex.");
        System.out.println("\t-salt\t\tSalts the hash with the specified <saltValue>");
        System.out.println("\t-times\t\tHashes the input <N> number of times");
    }

    private static boolean isReserved(String arg) {
        return "-base64".equals(arg) || "-times".equals(arg) || "-salt".equals(arg);
    }

    static int doMain(Class<? extends AbstractHash> clazz, String[] args) {
        String simple = clazz.getSimpleName();
        int index = simple.indexOf("Hash");
        String type = simple.substring(0, index).toUpperCase();

        if (args == null || args.length < 1 || args.length > 7) {
            printMainUsage(clazz, type);
            return -1;
        }
        boolean hex = true;
        String salt = null;
        int times = 1;
        String text = args[args.length - 1];
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-base64")) {
                hex = false;
            } else if (arg.equals("-salt")) {
                if ((i + 1) >= (args.length - 1)) {
                    String msg = "Salt argument must be followed by a salt value.  The final argument is " +
                            "reserved for the value to hash.";
                    System.out.println(msg);
                    printMainUsage(clazz, type);
                    return -1;
                }
                salt = args[i + 1];
            } else if (arg.equals("-times")) {
                if ((i + 1) >= (args.length - 1)) {
                    String msg = "Times argument must be followed by an integer value.  The final argument is " +
                            "reserved for the value to hash";
                    System.out.println(msg);
                    printMainUsage(clazz, type);
                    return -1;
                }
                try {
                    times = Integer.valueOf(args[i + 1]);
                } catch (NumberFormatException e) {
                    String msg = "Times argument must be followed by an integer value.";
                    System.out.println(msg);
                    printMainUsage(clazz, type);
                    return -1;
                }
            }
        }

        Hash hash = new Md2Hash(text, salt, times);
        String hashed = hex ? hash.toHex() : hash.toBase64();
        System.out.print(hex ? "Hex: " : "Base64: ");
        System.out.println(hashed);
        return 0;
    }
}
