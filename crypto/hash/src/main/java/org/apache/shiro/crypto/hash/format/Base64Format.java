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
package org.apache.shiro.crypto.hash.format;

import org.apache.shiro.crypto.hash.Hash;

import static java.util.Objects.requireNonNull;

/**
 * {@code HashFormat} that outputs <em>only</em> the hash's digest bytes in Base64 format.  It does not print out
 * anything else (salt, iterations, etc.).  This implementation is mostly provided as a convenience for
 * command-line hashing.
 *
 * @since 1.2
 * @deprecated will throw exceptions in 2.1.0, to be removed in 2.2.0
 */
@Deprecated
public class Base64Format implements HashFormat {

    /**
     * Returns {@code hash.toBase64()}.
     *
     * @param hash the hash instance to format into a String.
     * @return {@code hash.toBase64()}.
     * @throws NullPointerException if hash is {@code null}.
     */
    @Override
    public String format(final Hash hash) {
        return requireNonNull(hash).toBase64();
    }
}
