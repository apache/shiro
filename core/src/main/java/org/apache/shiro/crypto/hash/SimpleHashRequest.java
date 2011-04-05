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

import org.apache.shiro.util.ByteSource;

/**
 * Simple implementation of {@link HashRequest} that retains the {@link #getSource source} and
 * {@link #getSalt salt} properties as private attributes.
 *
 * @since 1.2
 */
public class SimpleHashRequest implements HashRequest {

    private final ByteSource source;
    private final ByteSource salt;

    /**
     * Creates a new {@code SimpleHashRequest} with the specified source to be hashed.
     *
     * @param source the source data to be hashed
     * @throws NullPointerException if the specified {@code source} argument is {@code null}.
     */
    public SimpleHashRequest(ByteSource source) throws NullPointerException {
        this(source, null);
    }

    /**
     * Creates a new {@code SimpleHashRequest} with the specified source and salt.
     *
     * @param source the source data to be hashed
     * @param salt   a salt a salt to be used by the {@link Hasher} during hash computation.
     * @throws NullPointerException if the specified {@code source} argument is {@code null}.
     */
    public SimpleHashRequest(ByteSource source, ByteSource salt) throws NullPointerException {
        this.source = source;
        this.salt = salt;
        if (source == null) {
            throw new NullPointerException("source argument cannot be null.");
        }
    }

    public ByteSource getSource() {
        return this.source;
    }

    public ByteSource getSalt() {
        return this.salt;
    }
}
