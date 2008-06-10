/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.authc.credential;

import org.jsecurity.crypto.hash.AbstractHash;
import org.jsecurity.crypto.hash.Md2Hash;

/**
 * @author Les Hazlewood
 * @since Jun 10, 2008 4:38:16 PM
 */
public class Md2CredentialsMatcherTest extends HashedCredentialsMatcherTest {

    public Class<? extends HashedCredentialsMatcher> getMatcherClass() {
        return Md2CredentialsMatcher.class;
    }

    public AbstractHash hash(Object credentials) {
        return new Md2Hash(credentials);
    }
}
