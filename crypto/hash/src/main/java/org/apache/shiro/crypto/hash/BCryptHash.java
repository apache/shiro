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
import java.util.List;
import java.util.Locale;
import java.util.StringJoiner;
import java.util.regex.Pattern;

import static java.util.Collections.unmodifiableList;

public class BCryptHash extends AbstractCryptHash {

    private static final long serialVersionUID = 6957869292324606101L;

    protected static final int DEFAULT_COST = 10;

    private static final String ALGORITHM_NAME = "2y";

    private static final int SALT_LENGTH = 16;

    private static final Pattern DELIMITER = Pattern.compile("\\$");

    private static final List<String> ALGORITHMS_BCRYPT = Arrays.asList("2", "2a", "2b", "2y");

    public BCryptHash(final byte[] hashedData, final ByteSource salt, final int iterations) {
        this(ALGORITHM_NAME, hashedData, salt, iterations);
    }

    public BCryptHash(final String version, final byte[] hashedData, final ByteSource salt, final int iterations) {
        super(version, hashedData, salt, iterations);
    }

    @Override
    protected final void checkValidAlgorithm() {
        if (!ALGORITHMS_BCRYPT.contains(getAlgorithmName())) {
            final String message = String.format(
                    Locale.ENGLISH,
                    "Given algorithm name [%s] not valid for bcrypt. " +
                            "Valid algorithms: [%s].",
                    getAlgorithmName(),
                    ALGORITHMS_BCRYPT
            );
            throw new IllegalArgumentException(message);
        }
    }

    @Override
    protected final void checkValidIterations() {
        double costDbl = Math.log10(this.getIterations()) / Math.log10(2);
        if ((costDbl != Math.floor(costDbl)) || Double.isInfinite(costDbl)) {
            throw new IllegalArgumentException("Iterations are not a power of 2. Found: [" + this.getIterations() + "].");
        }

        int cost = (int) costDbl;
        if (cost < 4 || cost > 31) {
            final String message = String.format(
                    Locale.ENGLISH,
                    "Expected bcrypt cost >= 4 and <=30, but was [%d].",
                    cost
            );
            throw new IllegalArgumentException(message);
        }

        double iterations = Math.pow(2, cost);
        if (iterations != getIterations()) {
            throw new IllegalArgumentException("Iterations are not a power of 2!");
        }
    }

    public int getCost() {
        double cost = Math.log10(this.getIterations()) / Math.log10(2);

        return (int) cost;
    }


    public static List<String> getAlgorithmsBcrypt() {
        return unmodifiableList(ALGORITHMS_BCRYPT);
    }

    public static BCryptHash generate(final char[] source) {
        return generate(source, createSalt(), DEFAULT_COST);
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
        final int iterations = (int) Math.pow(2, cost);

        final String dataSection = parts[2];
        final OpenBSDBase64.Default bcryptBase64 = new OpenBSDBase64.Default();
        final String saltBase64 = dataSection.substring(0, 22);
        final String bytesBase64 = dataSection.substring(22);
        final byte[] salt = bcryptBase64.decode(saltBase64.getBytes(StandardCharsets.ISO_8859_1));
        final byte[] hashedData = bcryptBase64.decode(bytesBase64.getBytes(StandardCharsets.ISO_8859_1));

        return new BCryptHash(algorithmName, hashedData, new SimpleByteSource(salt), iterations);
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
    public boolean matchesPassword(ByteSource plaintextBytes) {
        final String cryptString = OpenBSDBCrypt.generate(ALGORITHM_NAME, plaintextBytes.getBytes(), this.getSalt().getBytes(), this.getCost());

        return this.equals(fromCryptString(cryptString));
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", BCryptHash.class.getSimpleName() + "[", "]")
                .add("super=" + super.toString())
                .toString();
    }
}
