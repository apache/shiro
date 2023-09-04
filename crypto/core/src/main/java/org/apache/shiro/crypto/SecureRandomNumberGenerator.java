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
package org.apache.shiro.crypto;

import org.apache.shiro.lang.util.ByteSource;

import java.security.SecureRandom;

/**
 * Default implementation of the {@link RandomNumberGenerator RandomNumberGenerator} interface, backed by a
 * {@link SecureRandom SecureRandom} instance.
 * <p/>
 * This class is a little easier to use than using the JDK's {@code SecureRandom} class directly.  It also
 * allows for JavaBeans-style of customization, convenient for Shiro's INI configuration or other IoC configuration
 * mechanism.
 *
 * @since 1.1
 */
public class SecureRandomNumberGenerator implements RandomNumberGenerator {

    //16 bytes == 128 bits (a common number in crypto)
    protected static final int DEFAULT_NEXT_BYTES_SIZE = 16;

    private int defaultNextBytesSize;
    private SecureRandom secureRandom;

    /**
     * Creates a new instance with a default backing {@link SecureRandom SecureRandom} and a
     * {@link #getDefaultNextBytesSize() defaultNextBytesSize} of {@code 16}, which equals 128 bits, a size commonly
     * used in cryptographic algorithms.
     */
    public SecureRandomNumberGenerator() {
        this.defaultNextBytesSize = DEFAULT_NEXT_BYTES_SIZE;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Seeds the backing {@link SecureRandom SecureRandom} instance with additional seed data.
     *
     * @param bytes the seed bytes
     * @see SecureRandom#setSeed(byte[])
     */
    public void setSeed(byte[] bytes) {
        this.secureRandom.setSeed(bytes);
    }

    /**
     * Returns the {@link SecureRandom SecureRandom} backing this instance.
     *
     * @return the {@link SecureRandom SecureRandom} backing this instance.
     */
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    /**
     * Sets the {@link SecureRandom SecureRandom} to back this instance.
     *
     * @param random the {@link SecureRandom SecureRandom} to back this instance.
     * @throws NullPointerException if the method argument is null
     */
    public void setSecureRandom(SecureRandom random) throws NullPointerException {
        if (random == null) {
            throw new NullPointerException("SecureRandom argument cannot be null.");
        }
        this.secureRandom = random;
    }

    /**
     * Returns the size of the generated byte array for calls to {@link #nextBytes() nextBytes()}.  Defaults to
     * {@code 16}, which equals 128 bits, a size commonly used in cryptographic algorithms.
     *
     * @return the size of the generated byte array for calls to {@link #nextBytes() nextBytes()}.
     */
    public int getDefaultNextBytesSize() {
        return defaultNextBytesSize;
    }

    /**
     * Sets the size of the generated byte array for calls to {@link #nextBytes() nextBytes()}. Defaults to
     * {@code 16}, which equals 128 bits, a size commonly used in cryptographic algorithms.
     *
     * @param defaultNextBytesSize the size of the generated byte array for calls to {@link #nextBytes() nextBytes()}.
     * @throws IllegalArgumentException if the argument is 0 or negative
     */
    public void setDefaultNextBytesSize(int defaultNextBytesSize) throws IllegalArgumentException {
        if (defaultNextBytesSize <= 0) {
            throw new IllegalArgumentException("size value must be a positive integer (1 or larger)");
        }
        this.defaultNextBytesSize = defaultNextBytesSize;
    }

    public ByteSource nextBytes() {
        return nextBytes(getDefaultNextBytesSize());
    }

    public ByteSource nextBytes(int numBytes) {
        if (numBytes <= 0) {
            throw new IllegalArgumentException("numBytes argument must be a positive integer (1 or larger)");
        }
        byte[] bytes = new byte[numBytes];
        this.secureRandom.nextBytes(bytes);
        return ByteSource.Util.bytes(bytes);
    }
}
