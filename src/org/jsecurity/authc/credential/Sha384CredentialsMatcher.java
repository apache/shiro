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
import org.jsecurity.crypto.hash.Hash;
import org.jsecurity.crypto.hash.Sha384Hash;

/**
 * <tt>HashedCredentialsMatcher</tt> implementation that expects the stored <tt>Account</tt> credentials to be
 * SHA-384 hashed.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class Sha384CredentialsMatcher extends HashedCredentialsMatcher {

    protected AbstractHash newHashInstance() {
        return new Sha384Hash();
    }

    protected Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations ) {
        return new Sha384Hash( credentials, salt, hashIterations );
    }
}
