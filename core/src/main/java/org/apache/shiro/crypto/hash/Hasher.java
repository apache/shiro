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

/**
 * A {@code Hasher} hashes input sources utilizing a particular hashing strategy.
 * <p/>
 * A {@code Hasher} sits at a higher architectural level than Shiro's simple {@link Hash} classes:  it allows
 * for salting and iteration-related strategies to be configured and internalized in a
 * single component that can be re-used in multiple places in the application.
 * <p/>
 * For example, for the most secure hashes, it is highly recommended to use a randomly generated salt, potentially
 * paired with an configuration-specific private salt, in addition to using multiple hash iterations.
 * <p/>
 * While one can do this easily enough using Shiro's {@link Hash} implementations directly, this direct approach could
 * quickly lead to copy-and-paste behavior.  For example, consider this logic which might need to repeated in an
 * application:
 * <pre>
 * byte[] applicationSalt = ...
 * byte[] randomSalt = {@link org.apache.shiro.crypto.RandomNumberGenerator randomNumberGenerator}.nextBytes().getBytes();
 * byte[] combined = combine(applicationSalt, randomSalt);
 * ByteSource hash = Sha512Hash(source, combined, numHashIterations);
 * ByteSource salt = new SimpleByteSource(combined);
 * save(hash, salt);
 * </pre>
 * In this example, often only the input source will change during runtime, while the hashing strategy (how salts
 * are generated or acquired, how many hash iterations will be performed, etc) usually remain consistent.  A HashService
 * internalizes this logic so the above becomes simply this:
 * <pre>
 * HashResponse response = hasher.hash(source);
 * save(response.getHash(), response.getSalt());
 * </pre>
 *
 * @since 1.2
 */
public interface Hasher {

    /**
     * Computes a hash based on the given request.
     * <p/>
     * Note that the response data may not be the same as what would have been achieved by using a {@link Hash}
     * implementation directly.  See the
     * {@link org.apache.shiro.crypto.hash.HashResponse#getSalt() HashResponse.getSalt()} JavaDoc for more information.
     *
     * @param request the request to process
     * @return the hashed data as a {@code HashResponse}
     * @see org.apache.shiro.crypto.hash.HashResponse#getSalt()
     */
    HashResponse computeHash(HashRequest request);

}
