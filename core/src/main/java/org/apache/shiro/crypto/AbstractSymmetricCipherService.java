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

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Base abstract class for supporting symmetric key cipher algorithms.
 *
 * @since 1.0
 */
public abstract class AbstractSymmetricCipherService extends JcaCipherService {

    protected AbstractSymmetricCipherService(String algorithmName) {
        super(algorithmName);
    }

    /**
     * Generates a new {@link java.security.Key Key} suitable for this CipherService's {@link #getAlgorithmName() algorithm}
     * by calling {@link #generateNewKey(int) generateNewKey(128)} (uses a 128 bit size by default).
     *
     * @return a new {@link java.security.Key Key}, 128 bits in length.
     */
    public Key generateNewKey() {
        return generateNewKey(getKeySize());
    }

    /**
     * Generates a new {@link Key Key} of the specified size suitable for this CipherService
     * (based on the {@link #getAlgorithmName() algorithmName} using the JDK {@link javax.crypto.KeyGenerator KeyGenerator}.
     *
     * @param keyBitSize the bit size of the key to create
     * @return the created key suitable for use with this CipherService
     */
    public Key generateNewKey(int keyBitSize) {
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance(getAlgorithmName());
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unable to acquire " + getAlgorithmName() + " algorithm.  This is required to function.";
            throw new IllegalStateException(msg, e);
        }
        kg.init(keyBitSize);
        return kg.generateKey();
    }

}
