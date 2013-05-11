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
package org.apache.shiro.authc.credential;

import org.apache.shiro.crypto.hash.AbstractHash;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.Sha384Hash;


/**
 * {@code HashedCredentialsMatcher} implementation that expects the stored {@code AuthenticationInfo} credentials to be
 * SHA-384 hashed.
 *
 * @since 0.9
 * @deprecated since 1.1 - use the HashedCredentialsMatcher directly and set its
 *             {@link HashedCredentialsMatcher#setHashAlgorithmName(String) hashAlgorithmName} property.
 */
public class Sha384CredentialsMatcher extends HashedCredentialsMatcher {

    public Sha384CredentialsMatcher() {
        super();
        setHashAlgorithmName(Sha384Hash.ALGORITHM_NAME);
    }
}
