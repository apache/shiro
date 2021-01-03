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

import org.apache.shiro.lang.codec.OpenBSDBase64;
import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.SimpleByteSource;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.StringJoiner;
import java.util.regex.Pattern;

public class BCryptHash extends AbstractCryptHash {

    private static final long serialVersionUID = 6957869292324606101L;

    protected static final int DEFAULT_ITERATIONS = 10;

    private static final String ALGORITHM_NAME = "2y";

    private static final int SALT_LENGTH = 16;

    private static final Pattern DELIMITER = Pattern.compile("\\$");

    private final String version;
    private final ByteSource salt;
    private final byte[] hashedData;
    private final int cost;


    public BCryptHash(final byte[] hashedData, final ByteSource salt, final int cost) {
        this(ALGORITHM_NAME, hashedData, salt, cost);
    }

    public BCryptHash(final String version, final byte[] hashedData, final ByteSource salt, final int cost) {
        super();
        this.version = version;
        this.hashedData = Arrays.copyOf(hashedData, hashedData.length);
        this.salt = salt;
        this.cost = cost;
    }

    public static BCryptHash generate(final char[] source) {
        return generate(source, createSalt(), DEFAULT_ITERATIONS);
    }


    public static BCryptHash generate(final char[] source, final byte[] initialSalt, final int cost) {
        final String cryptString = OpenBSDBCrypt.generate(ALGORITHM_NAME, source, initialSalt, cost);

        return fromCryptString(cryptString);
    }

    private static BCryptHash fromCryptString(String cryptString) {
        String[] parts = DELIMITER.split(cryptString.substring(1), -1);

        if (parts.length != 3) {
            throw new IllegalArgumentException("Expected string containing three '$' but got: '" + Arrays.toString(parts) + "'.");
        }

        final String algorithmName = parts[0];
        final int cost = Integer.parseInt(parts[1], 10);
        final String dataSection = parts[2];
        final OpenBSDBase64.Default bcryptBase64 = new OpenBSDBase64.Default();
        final String saltBase64 = dataSection.substring(0, 22);
        final String bytesBase64 = dataSection.substring(22);
        final byte[] salt = bcryptBase64.decode(saltBase64.getBytes(StandardCharsets.ISO_8859_1));
        final byte[] hashedData = bcryptBase64.decode(bytesBase64.getBytes(StandardCharsets.ISO_8859_1));

        return new BCryptHash(algorithmName, hashedData, new SimpleByteSource(salt), cost);
    }

    protected static byte[] createSalt() {
        return new SecureRandom().generateSeed(SALT_LENGTH);
    }

    @Override
    public String getAlgorithmName() {
        return ALGORITHM_NAME;
    }

    @Override
    public int getSaltLength() {
        return SALT_LENGTH;
    }

    @Override
    public ByteSource getSalt() {
        return this.salt;
    }

    /**
     * <strong>Warning!</strong> The returned value is actually the cost, not the iterations.
     *
     * @return the cost.
     */
    @Override
    public int getIterations() {
        return this.getCost();
    }

    @Override
    public boolean matchesPassword(ByteSource plaintextBytes) {
        final String cryptString = OpenBSDBCrypt.generate(ALGORITHM_NAME, plaintextBytes.getBytes(), this.salt.getBytes(), cost);

        return this.equals(fromCryptString(cryptString));
    }

    public int getRealIterations() {
        return (int) Math.pow(2, this.getCost());
    }

    public int getCost() {
        return this.cost;
    }

    @Override
    public byte[] getBytes() {
        return Arrays.copyOf(this.hashedData, this.hashedData.length);
    }

    @Override
    public boolean isEmpty() {
        return false;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", BCryptHash.class.getSimpleName() + "[", "]")
                .add("super=" + super.toString())
                .add("version='" + this.version + "'")
                .add("salt=" + Arrays.toString(this.salt.getBytes()))
                .add("hashedData=" + Arrays.toString(this.hashedData))
                .add("cost=" + this.cost)
                .toString();
    }
}
