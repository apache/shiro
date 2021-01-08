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

import java.util.Optional;
import java.util.ServiceLoader;
import java.util.stream.StreamSupport;

import static java.util.Objects.requireNonNull;

/**
 * Hashes used by the Shiro2CryptFormat class.
 *
 * <p>Instead of maintaining them as an {@code Enum}, ServiceLoaders would provide a pluggable alternative.</p>
 */
public final class HashProvider {

    private HashProvider() {
        // utility class
    }

    /**
     * Find a KDF implementation by searching the algorithms.
     *
     * @param algorithmName the algorithmName to match. This is case-sensitive.
     * @return an instance of {@link HashProvider} if found, otherwise {@link Optional#empty()}.
     * @throws NullPointerException if the given parameter algorithmName is {@code null}.
     */
    public static Optional<HashSpi<? extends Hash>> getByAlgorithmName(String algorithmName) {
        requireNonNull(algorithmName, "algorithmName in HashProvider.getByAlgorithmName");
        ServiceLoader<HashSpi<? extends Hash>> hashSpis = load();

        return StreamSupport.stream(hashSpis.spliterator(), false)
                .filter(hashSpi -> hashSpi.getImplementedAlgorithms().contains(algorithmName))
                .findAny();
    }

    @SuppressWarnings("unchecked")
    private static ServiceLoader<HashSpi<? extends Hash>> load() {
        return (ServiceLoader<HashSpi<? extends Hash>>) (Object) ServiceLoader.load(HashSpi.class);
    }

}
