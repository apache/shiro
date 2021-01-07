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

import static java.util.Collections.unmodifiableList;

public class BCryptHash extends AbstractCryptHash {

    private static final long serialVersionUID = 6957869292324606101L;

    protected static final int DEFAULT_COST = 10;

    private static final String ALGORITHM_NAME = "2y";

    private static final int SALT_LENGTH = 16;

    private static final List<String> ALGORITHMS_BCRYPT = Arrays.asList("2", "2a", "2b", "2y");

    private final int cost;

    private final int iterations;

    public BCryptHash(final String version, final byte[] hashedData, final ByteSource salt, final int cost) {
        super(version, hashedData, salt);
        this.cost = cost;
        this.iterations = (int) Math.pow(2, cost);
        checkValidCost();
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

    protected final void checkValidCost() {
        checkValidCost(this.cost);
    }

    private static void checkValidCost(final int cost) {
        if (cost < 4 || cost > 31) {
            final String message = String.format(
                    Locale.ENGLISH,
                    "Expected bcrypt cost >= 4 and <=30, but was [%d].",
                    cost
            );
            throw new IllegalArgumentException(message);
        }
    }

    public int getCost() {
        return this.cost;
    }

    public static List<String> getAlgorithmsBcrypt() {
        return unmodifiableList(ALGORITHMS_BCRYPT);
    }

    public static BCryptHash fromString(String input) {
        // the input string should look like this:
        // $2y$cost$salt{22}hash
        if (!input.startsWith("$")) {
            throw new UnsupportedOperationException("Unsupported input: " + input);
        }

        final String[] parts = DELIMITER.split(input.substring(1));

        if (parts.length != 3) {
            throw new IllegalArgumentException("Expected string containing three '$' but got: '" + Arrays.toString(parts) + "'.");
        }
        final String algorithmName = parts[0].trim();
        final int cost = Integer.parseInt(parts[1].trim(), 10);

        final String dataSection = parts[2];
        final OpenBSDBase64.Default bcryptBase64 = new OpenBSDBase64.Default();

        final String saltBase64 = dataSection.substring(0, 22);
        final String bytesBase64 = dataSection.substring(22);
        final byte[] salt = bcryptBase64.decode(saltBase64.getBytes(StandardCharsets.ISO_8859_1));
        final byte[] hashedData = bcryptBase64.decode(bytesBase64.getBytes(StandardCharsets.ISO_8859_1));

        return new BCryptHash(algorithmName, hashedData, new SimpleByteSource(salt), cost);
    }

    public static BCryptHash generate(final ByteSource source) {
        return generate(source, createSalt(), DEFAULT_COST);
    }


    public static BCryptHash generate(final ByteSource source, final ByteSource initialSalt, final int cost) {
        return generate(ALGORITHM_NAME, source, initialSalt, cost);
    }

    public static BCryptHash generate(String algorithmName, ByteSource source, ByteSource salt, int cost) {
        checkValidCost(cost);
        final String cryptString = OpenBSDBCrypt.generate(algorithmName, source.getBytes(), salt.getBytes(), cost);

        return fromString(cryptString);
    }

    protected static ByteSource createSalt() {
        return new SimpleByteSource(new SecureRandom().generateSeed(SALT_LENGTH));
    }

    @Override
    public int getSaltLength() {
        return SALT_LENGTH;
    }

    @Override
    public String formatToCryptString() {
        OpenBSDBase64.Default bsdBase64 = new OpenBSDBase64.Default();
        String saltBase64 = new String(bsdBase64.encode(this.getSalt().getBytes()), StandardCharsets.ISO_8859_1);
        String dataBase64 = new String(bsdBase64.encode(this.getBytes()), StandardCharsets.ISO_8859_1);

        return new StringJoiner("$", "$", "")
                .add(this.getAlgorithmName())
                .add("" + this.cost)
                .add(saltBase64 + dataBase64)
                .toString();
    }

    @Override
    public int getIterations() {
        return this.iterations;
    }

    @Override
    public boolean matchesPassword(ByteSource plaintextBytes) {
        final String cryptString = OpenBSDBCrypt.generate(this.getAlgorithmName(), plaintextBytes.getBytes(), this.getSalt().getBytes(), this.getCost());
        BCryptHash other = fromString(cryptString);

        return this.equals(other);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", BCryptHash.class.getSimpleName() + "[", "]")
                .add("super=" + super.toString())
                .add("cost=" + this.cost)
                .toString();
    }
}
