/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc.credential;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * Default implementation of the {@link PasswordService} interface.
 *
 * @since 1.2
 */
public class DefaultPasswordService implements PasswordService {

    public static final String DEFAULT_HASH_ALGORITHM_NAME = "SHA-512";
    //see http://www.katasoft.com/blog/2011/04/04/strong-password-hashing-apache-shiro
    public static final int DEFAULT_HASH_ITERATIONS = 500000; //500,000
    public static final int DEFAULT_SALT_SIZE = 32; //32 bytes == 256 bits

    private static final String MCF_PREFIX = "$shiro1$"; //Modular Crypt Format prefix specific to Shiro's needs

    private static final Logger log = LoggerFactory.getLogger(DefaultPasswordService.class);

    private String hashAlgorithmName;
    private int hashIterations;
    private int saltSize;
    private RandomNumberGenerator randomNumberGenerator;

    public DefaultPasswordService() {
        this.hashAlgorithmName = DEFAULT_HASH_ALGORITHM_NAME;
        this.hashIterations = DEFAULT_HASH_ITERATIONS;
        this.saltSize = DEFAULT_SALT_SIZE;
        this.randomNumberGenerator = new SecureRandomNumberGenerator();
    }

    public String hashPassword(String plaintext) {
        if (plaintext == null || plaintext.length() == 0) {
            return null;
        }
        return hashPassword(ByteSource.Util.bytes(plaintext));
    }

    public String hashPassword(ByteSource plaintext) {
        if (plaintext == null) {
            return null;
        }
        byte[] plaintextBytes = plaintext.getBytes();
        if (plaintextBytes == null || plaintextBytes.length == 0) {
            return null;
        }
        String algorithmName = getHashAlgorithmName();
        ByteSource salt = getRandomNumberGenerator().nextBytes(getSaltSize());
        int iterations = Math.max(1, getHashIterations());

        Hash result = new SimpleHash(algorithmName, plaintext, salt, iterations);

        //Modular Crypt Format
        //TODO: make this pluggable:
        return new StringBuilder(MCF_PREFIX).append(algorithmName).append("$").append(iterations).append("$")
                .append(salt.toBase64()).append("$").append(result.toBase64()).toString();
    }

    public boolean passwordsMatch(ByteSource submittedPassword, String savedPassword) {
        if (savedPassword == null) {
            return isEmpty(submittedPassword);
        } else {
            return !isEmpty(submittedPassword) && doPasswordsMatch(submittedPassword, savedPassword);
        }
    }

    private static boolean isEmpty(ByteSource source) {
        return source == null || source.getBytes() == null || source.getBytes().length == 0;
    }

    private boolean doPasswordsMatch(ByteSource submittedPassword, String savedPassword) {
        if (!savedPassword.startsWith(MCF_PREFIX)) {
            log.warn("Encountered unrecognized saved password format.  Falling back to simple equality " +
                    "comparison.  Use the PasswordService to hash new passwords as well as match them.");
            return ByteSource.Util.bytes(savedPassword).equals(submittedPassword);
        }

        String suffix = savedPassword.substring(MCF_PREFIX.length());
        String[] parts = suffix.split("\\$");

        //last part is always the digest/checksum, Base64-encoded:
        int i = parts.length-1;
        String digestBase64 = parts[i--];
        //second-to-last part is always the salt, Base64-encoded:
        String saltBase64 = parts[i--];
        String iterationsString = parts[i--];
        String algorithmName = parts[i--];

        /*String timestampString = null;

        if (parts.length == 5) {
            timestampString = parts[i--];
        } */

        byte[] digest = Base64.decode(digestBase64);

        byte[] salt = Base64.decode(saltBase64);
        int iterations;
        try {
            iterations = Integer.parseInt(iterationsString);
        } catch (NumberFormatException e) {
            log.error("Unable to parse saved password string: " + savedPassword, e);
            throw e;
        }

        //now compute the digest on the submitted password.  If the resulting digest matches the saved digest,
        //the password matches:

        Hash submittedHash = new SimpleHash(algorithmName, submittedPassword, salt, iterations);

        return Arrays.equals(digest, submittedHash.getBytes());
    }

    public String getHashAlgorithmName() {
        return hashAlgorithmName;
    }

    public void setHashAlgorithmName(String hashAlgorithmName) {
        this.hashAlgorithmName = hashAlgorithmName;
    }

    public int getHashIterations() {
        return hashIterations;
    }

    public void setHashIterations(int hashIterations) {
        this.hashIterations = hashIterations;
    }

    public int getSaltSize() {
        return saltSize;
    }

    public void setSaltSize(int saltSize) {
        this.saltSize = saltSize;
    }

    public RandomNumberGenerator getRandomNumberGenerator() {
        return randomNumberGenerator;
    }

    public void setRandomNumberGenerator(RandomNumberGenerator randomNumberGenerator) {
        this.randomNumberGenerator = randomNumberGenerator;
    }
}
