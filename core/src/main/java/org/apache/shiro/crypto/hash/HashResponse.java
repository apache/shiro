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
 * A {@code HashResponse} represents the data returned from a {@link Hasher} after hashing an input source.
 * <p/>
 * Note that a {@code HashResposne} may not represent identical output compared to using Shiro's {@link Hash}
 * implementations directly.  See the {@link #getSalt() getHashSalt()} JavaDoc for further explanation.
 *
 * @since 1.2
 */
public interface HashResponse {

    /**
     * Returns the hashed data returned by the {@link Hasher}.
     *
     * @return the hashed data returned by the {@link Hasher}.
     */
    Hash getHash();

    /**
     * Returns a salt used by the servicing {@link Hasher} when hashing the input source.  This same salt must be
     * presented back to the {@code Hasher} if hash comparison/verification will be performed (for example, for
     * password hash or file checksum comparisons).
     * <p/>
     * Note that the salt returned from this method <em>MAY NOT</em> be the exact same salt used to compute the
     * {@link #getHash() hash}.  Such a thing is common when performing password hashes for example: if the
     * {@code Hasher} uses internal/private salt data in addition to a specified or random salt, the complete salt
     * should not be accessible with the password hash.  If it was, brute force attacks could more easily
     * compromise passwords.  If part of the salt was not accessible to an attacker (because it is not stored with the
     * password), brute-force attacks are <em>much</em> harder to execute.
     * </p>
     * This scenario emphasizes that any salt returned from this method should be re-supplied to the same {@code Hasher}
     * that computed the original hash if performing comparison/verification.  The alternative of, say, using a
     * Shiro {@link Hash} implementation directly to perform hash comparisons will likely fail.
     * <p/>
     * In summary, if a {@link Hasher} returns a salt in a response, it is expected that the same salt
     * will be provided to the same {@code Hasher} instance.
     *
     * @return salt a salt used by the {@link Hasher} when hashing the input source.
     */
    ByteSource getSalt();

}
