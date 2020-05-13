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
package org.apache.shiro.crypto.hash;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.lang.util.ByteSource;

/**
 * A {@code HashService} that allows configuration of its strategy via JavaBeans-compatible setter methods.
 *
 * @since 1.2
 */
public interface ConfigurableHashService extends HashService {

    /**
     * Sets the 'private' (internal) salt to be paired with a 'public' (random or supplied) salt during hash computation.
     *
     * @param privateSalt the 'private' internal salt to be paired with a 'public' (random or supplied) salt during
     *                    hash computation.
     */
    void setPrivateSalt(ByteSource privateSalt);

    /**
     * Sets the number of hash iterations that will be performed during hash computation.
     *
     * @param iterations the number of hash iterations that will be performed during hash computation.
     */
    void setHashIterations(int iterations);

    /**
     * Sets the name of the {@link java.security.MessageDigest MessageDigest} algorithm that will be used to compute
     * hashes.
     *
     * @param name the name of the {@link java.security.MessageDigest MessageDigest} algorithm that will be used to
     *             compute hashes.
     */
    void setHashAlgorithmName(String name);

    /**
     * Sets a source of randomness used to generate public salts that will in turn be used during hash computation.
     *
     * @param rng a source of randomness used to generate public salts that will in turn be used during hash computation.
     */
    void setRandomNumberGenerator(RandomNumberGenerator rng);
}
