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

import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.HashService;
import org.apache.shiro.crypto.hash.format.DefaultHashFormatFactory;
import org.apache.shiro.crypto.hash.format.HashFormat;
import org.apache.shiro.crypto.hash.format.HashFormatFactory;
import org.apache.shiro.crypto.hash.format.ParsableHashFormat;
import org.apache.shiro.crypto.hash.format.Shiro2CryptFormat;
import org.apache.shiro.lang.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;

import static java.util.Objects.requireNonNull;

/**
 * Default implementation of the {@link PasswordService} interface that relies on an internal
 * {@link HashService}, {@link HashFormat}, and {@link HashFormatFactory} to function:
 * <h2>Hashing Passwords</h2>
 *
 * <h2>Comparing Passwords</h2>
 * All hashing operations are performed by the internal {@link #getHashService() hashService}.
 *
 * @since 1.2
 */
public class DefaultPasswordService implements HashingPasswordService {

    public static final String DEFAULT_HASH_ALGORITHM = "argon2id";

    private static final Logger log = LoggerFactory.getLogger(DefaultPasswordService.class);

    private HashService hashService;
    private HashFormat hashFormat;
    private HashFormatFactory hashFormatFactory;

    private volatile boolean hashFormatWarned; //used to avoid excessive log noise

    /**
     * Constructs a new PasswordService with a default hash service and the default
     * algorithm name {@value #DEFAULT_HASH_ALGORITHM}, a default hash format (shiro2) and
     * a default hashformat factory.
     *
     * <p>The default algorithm can change between minor versions and does not introduce
     * API incompatibility by design.</p>
     */
    public DefaultPasswordService() {
        this.hashFormatWarned = false;

        DefaultHashService hashService = new DefaultHashService();
        hashService.setDefaultAlgorithmName(DEFAULT_HASH_ALGORITHM);
        this.hashService = hashService;

        this.hashFormat = new Shiro2CryptFormat();
        this.hashFormatFactory = new DefaultHashFormatFactory();
    }

    @Override
    public String encryptPassword(Object plaintext) {
        Hash hash = hashPassword(requireNonNull(plaintext));
        checkHashFormatDurability();
        return this.hashFormat.format(hash);
    }

    @Override
    public Hash hashPassword(Object plaintext) {
        ByteSource plaintextBytes = createByteSource(plaintext);
        if (plaintextBytes == null || plaintextBytes.isEmpty()) {
            return null;
        }
        HashRequest request = createHashRequest(plaintextBytes);
        return hashService.computeHash(request);
    }

    @Override
    public boolean passwordsMatch(Object plaintext, Hash saved) {
        ByteSource plaintextBytes = createByteSource(plaintext);

        if (saved == null || saved.isEmpty()) {
            return plaintextBytes == null || plaintextBytes.isEmpty();
        } else {
            if (plaintextBytes == null || plaintextBytes.isEmpty()) {
                return false;
            }
        }

        return saved.matchesPassword(plaintextBytes);
    }

    private boolean constantEquals(String savedHash, String computedHash) {

        byte[] savedHashByteArray = savedHash.getBytes();
        byte[] computedHashByteArray = computedHash.getBytes();

        return MessageDigest.isEqual(savedHashByteArray, computedHashByteArray);
    }

    protected void checkHashFormatDurability() {

        if (!this.hashFormatWarned) {

            HashFormat format = this.hashFormat;

            if (!(format instanceof ParsableHashFormat) && log.isWarnEnabled()) {
                String msg = "The configured hashFormat instance [" + format.getClass().getName() + "] is not a " +
                        ParsableHashFormat.class.getName() + " implementation.  This is " +
                        "required if you wish to support backwards compatibility for saved password checking (almost " +
                        "always desirable).  Without a " + ParsableHashFormat.class.getSimpleName() + " instance, " +
                        "any hashService configuration changes will break previously hashed/saved passwords.";
                log.warn(msg);
                this.hashFormatWarned = true;
            }
        }
    }

    protected HashRequest createHashRequest(ByteSource plaintext) {
        return new HashRequest.Builder().setSource(plaintext).build();
    }

    protected ByteSource createByteSource(Object o) {
        return ByteSource.Util.bytes(o);
    }

    @Override
    public boolean passwordsMatch(Object submittedPlaintext, String saved) {
        ByteSource plaintextBytes = createByteSource(submittedPlaintext);

        if (saved == null || saved.length() == 0) {
            return plaintextBytes == null || plaintextBytes.isEmpty();
        } else {
            if (plaintextBytes == null || plaintextBytes.isEmpty()) {
                return false;
            }
        }

        //First check to see if we can reconstitute the original hash - this allows us to
        //perform password hash comparisons even for previously saved passwords that don't
        //match the current HashService configuration values.  This is a very nice feature
        //for password comparisons because it ensures backwards compatibility even after
        //configuration changes.
        HashFormat discoveredFormat = this.hashFormatFactory.getInstance(saved);

        if (discoveredFormat instanceof ParsableHashFormat) {

            ParsableHashFormat parsableHashFormat = (ParsableHashFormat) discoveredFormat;
            Hash savedHash = parsableHashFormat.parse(saved);

            return passwordsMatch(submittedPlaintext, savedHash);
        }

        //If we're at this point in the method's execution, We couldn't reconstitute the original hash.
        //So, we need to hash the submittedPlaintext using current HashService configuration and then
        //compare the formatted output with the saved string.  This will correctly compare passwords,
        //but does not allow changing the HashService configuration without breaking previously saved
        //passwords:

        //The saved text value can't be reconstituted into a Hash instance.  We need to format the
        //submittedPlaintext and then compare this formatted value with the saved value:
        HashRequest request = createHashRequest(plaintextBytes);
        Hash computed = this.hashService.computeHash(request);
        String formatted = this.hashFormat.format(computed);

        return constantEquals(saved, formatted);
    }

    public HashService getHashService() {
        return hashService;
    }

    public void setHashService(HashService hashService) {
        this.hashService = hashService;
    }

    public HashFormat getHashFormat() {
        return hashFormat;
    }

    public void setHashFormat(HashFormat hashFormat) {
        this.hashFormat = hashFormat;
    }

    public HashFormatFactory getHashFormatFactory() {
        return hashFormatFactory;
    }

    public void setHashFormatFactory(HashFormatFactory hashFormatFactory) {
        this.hashFormatFactory = hashFormatFactory;
    }
}
