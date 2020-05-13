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
package org.apache.shiro.crypto;

import org.apache.shiro.lang.util.ByteSource;

/**
 * A component that can generate random number/byte values as needed.  Useful in cryptography or security scenarios
 * where random byte arrays are needed, such as for password salts, nonces, initialization vectors and other seeds.
 * <p/>
 * This is essentially the same as a {@link java.security.SecureRandom SecureRandom}, and indeed implementations
 * of this interface will probably all use {@link java.security.SecureRandom SecureRandom} instances, but this
 * interface provides a few additional benefits to end-users:
 * <ul>
 * <li>It is an interface rather than the JDK's {@code SecureRandom} concrete implementation.  Implementation details
 * can be customized as necessary based on the application's needs</li>
 * <li>Default per-instance behavior can be customized on implementations, typically via JavaBeans mutators.</li>
 * <li>Perhaps most important for Shiro end-users, tt can more easily be used as a source of cryptographic seed data,
 * and the data returned is already in a more convenient {@link ByteSource ByteSource} format in case that data needs
 * to be {@link org.apache.shiro.lang.util.ByteSource#toHex() hex} or
 * {@link org.apache.shiro.lang.util.ByteSource#toBase64() base64}-encoded.</li>
 * </ul>
 * For example, consider the following example generating password salts for new user accounts:
 * <pre>
 * RandomNumberGenerator saltGenerator = new {@link org.apache.shiro.crypto.SecureRandomNumberGenerator SecureRandomNumberGenerator}();
 * User user = new User();
 * user.setPasswordSalt(saltGenerator.nextBytes().toBase64());
 * userDAO.save(user);
 * </pre>
 *
 * @since 1.1
 */
public interface RandomNumberGenerator {

    /**
     * Generates a byte array of fixed length filled with random data, often useful for generating salts,
     * initialization vectors or other seed data.  The length is specified as a configuration
     * value on the underlying implementation.
     * <p/>
     * If you'd like per-invocation control the number of bytes generated, use the
     * {@link #nextBytes(int) nextBytes(int)} method instead.
     *
     * @return a byte array of fixed length filled with random data.
     * @see #nextBytes(int)
     */
    ByteSource nextBytes();

    /**
     * Generates a byte array of the specified length filled with random data.
     *
     * @param numBytes the number of bytes to be populated with random data.
     * @return a byte array of the specified length filled with random data.
     * @see #nextBytes()
     */
    ByteSource nextBytes(int numBytes);
}
