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

import org.apache.shiro.lang.util.ByteSource;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;

/**
 * Simple implementation of {@link HashRequest} that can be used when interacting with a {@link HashService}.
 *
 * @since 1.2
 */
public class SimpleHashRequest implements HashRequest {

    /**
     * cannot be null - this is the source to hash.
     */
    private final ByteSource source;
    /**
     * can be null = no salt specified
     */
    private final ByteSource salt;
    /**
     * can be null = let the HashService decide.
     */
    private final String algorithmName;
    private final Map<String, Object> parameters = new ConcurrentHashMap<>();

    /**
     * Creates a new SimpleHashRequest instance.
     *
     * @param algorithmName the name of the hash algorithm to use.  This is often null as the
     *                      {@link HashService} implementation is usually configured with an appropriate algorithm name, but this
     *                      can be non-null if the hash service's algorithm should be overridden with a specific one for the duration
     *                      of the request.
     * @param source        the source to be hashed
     * @param salt          any public salt which should be used when computing the hash
     * @param parameters    e.g. the number of hash iterations to execute or other parameters.
     * @throws NullPointerException if {@code source} is null or empty or {@code parameters} is {@code null}.
     */
    public SimpleHashRequest(String algorithmName, ByteSource source, ByteSource salt, Map<String, Object> parameters) {
        this.source = requireNonNull(source);
        this.salt = salt;
        this.algorithmName = algorithmName;
        this.parameters.putAll(requireNonNull(parameters));
    }

    @Override
    public ByteSource getSource() {
        return this.source;
    }

    @Override
    public Optional<ByteSource> getSalt() {
        return Optional.ofNullable(this.salt);
    }


    @Override
    public Optional<String> getAlgorithmName() {
        return Optional.ofNullable(algorithmName);
    }

    @Override
    public Map<String, Object> getParameters() {
        return unmodifiableMap(this.parameters);
    }
}
