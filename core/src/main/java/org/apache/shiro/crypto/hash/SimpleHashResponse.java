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
 * Simple implementation of {@link HashResponse} that retains the {@link #getHash hash} and
 * {@link #getSalt hashSalt} properties as private attributes.
 *
 * @since 1.2
 */
public class SimpleHashResponse implements HashResponse {

    private final Hash hash;
    private final ByteSource salt;

    /**
     * Constructs a new instance with the specified hash and salt.
     *
     * @param hash the hash to respond with.
     * @param salt the public salt associated with the specified hash.
     */
    public SimpleHashResponse(Hash hash, ByteSource salt) {
        this.hash = hash;
        this.salt = salt;
    }

    public Hash getHash() {
        return this.hash;
    }

    public ByteSource getSalt() {
        return this.salt;
    }
}
