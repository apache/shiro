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
package org.ki.authc.credential;

import org.ki.crypto.hash.AbstractHash;
import org.ki.crypto.hash.Sha512Hash;

/**
 * @author Les Hazlewood
 * @since Jun 10, 2008 5:02:58 PM
 */
public class Sha512CredentialsMatcherTest extends HashedCredentialsMatcherTest {

    public Class<? extends HashedCredentialsMatcher> getMatcherClass() {
        return Sha512CredentialsMatcher.class;
    }

    public AbstractHash hash(Object credentials) {
        return new Sha512Hash(credentials);
    }
}
