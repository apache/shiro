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
 * A {@code HashService} hashes input sources utilizing a particular hashing strategy.
 * <p/>
 * A {@code HashService} sits at a higher architectural level than Shiro's simple {@link Hash} classes:  it allows
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
 * int numHashIterations = ...
 * ByteSource privateSalt = ...
 * ByteSource randomSalt = {@link org.apache.shiro.crypto.RandomNumberGenerator randomNumberGenerator}.nextBytes();
 * ByteSource combined = combine(privateSalt, randomSalt);
 * Hash hash = Sha512Hash(source, combined, numHashIterations);
 * save(hash);
 * </pre>
 * In this example, often only the input source will change during runtime, while the hashing strategy (how salts
 * are generated or acquired, how many hash iterations will be performed, etc) usually remain consistent.  A HashService
 * internalizes this logic so the above becomes simply this:
 * <pre>
 * HashRequest request = new HashRequest.Builder().source(source).build();
 * Hash result = hashService.hash(request);
 * save(result);
 * </pre>
 *
 * @since 1.2
 */
public interface HashService {

    /**
     * Computes a hash based on the given request.
     *
     * <h3>Salt Notice</h3>
     *
     * If a salt accompanies the return value
     * (i.e. <code>returnedHash.{@link org.apache.shiro.crypto.hash.Hash#getSalt() getSalt()} != null</code>), this
     * same exact salt <b><em>MUST</em></b> be presented back to the {@code HashService} if hash
     * comparison/verification will be performed at a later time (for example, for password hash or file checksum
     * comparison).
     * <p/>
     * For additional security, the {@code HashService}'s internal implementation may use more complex salting
     * strategies than what would be achieved by computing a {@code Hash} manually.
     * <p/>
     * In summary, if a {@link HashService} returns a salt in a returned Hash, it is expected that the same salt
     * will be provided to the same {@code HashService} instance.
     *
     * @param request the request to process
     * @return the hashed data
     * @see Hash#getSalt()
     */
    Hash computeHash(HashRequest request);
}
