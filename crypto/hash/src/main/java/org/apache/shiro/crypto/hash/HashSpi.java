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

import java.util.Random;
import java.util.Set;

/**
 * Service Provider Interface for password hashing algorithms.
 *
 * <p>Apache Shiro will load algorithm implementations based on the method {@link #getImplementedAlgorithms()}.
 * Loaded providers are expected to return a suitable hash implementation.</p>
 *
 * <p>Modern kdf-based hash implementations can extend the {@link AbstractCryptHash} class.</p>
 *
 * @since 2.0.0
 */
public interface HashSpi {

    /**
     * A list of algorithms recognized by this implementation.
     *
     * <p>Example values are {@code argon2id} and {@code argon2i} for the Argon2 service provider and
     * {@code 2y} and {@code 2a} for the BCrypt service provider.</p>
     *
     * @return a set of recognized algorithms.
     */
    Set<String> getImplementedAlgorithms();

    /**
     * Creates a Hash instance from the given format string recognized by this provider.
     *
     * <p>There is no global format which this provider must accept. Each provider can define their own
     * format, but they are usually based on the {@code crypt(3)} formats used in {@code /etc/shadow} files.</p>
     *
     * <p>Implementations should overwrite this javadoc to add examples of the accepted formats.</p>
     *
     * @param format the format string to be parsed by this implementation.
     * @return a class extending Hash.
     */
    Hash fromString(String format);

    /**
     * A factory class for the hash of the type {@code <T>}.
     *
     * <p>Implementations are highly encouraged to use the given random parameter as
     * source of random bytes (e.g. for seeds).</p>
     *
     * @param random a source of {@link Random}, usually {@code SecureRandom}.
     * @return a factory class for creating instances of {@code <T>}.
     */
    HashFactory newHashFactory(Random random);

    interface HashFactory {

        Hash generate(HashRequest hashRequest);
    }
}
