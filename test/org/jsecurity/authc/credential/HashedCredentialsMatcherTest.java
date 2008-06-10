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

import junit.framework.TestCase;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.SimpleAccount;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.crypto.hash.AbstractHash;
import org.jsecurity.util.ClassUtils;
import org.junit.Test;

/**
 * @author Les Hazlewood
 * @since Jun 10, 2008 4:47:09 PM
 */
public abstract class HashedCredentialsMatcherTest extends TestCase {

    public abstract Class<? extends HashedCredentialsMatcher> getMatcherClass();

    public abstract AbstractHash hash(Object credentials);

    @Test
    public void testBasic() {
        CredentialsMatcher matcher = (CredentialsMatcher) ClassUtils.newInstance(getMatcherClass());
        byte[] hashed = hash("password").getBytes();
        Account account = new SimpleAccount("username", hashed, "realmName");
        AuthenticationToken token = new UsernamePasswordToken("username", "password");
        assertTrue(matcher.doCredentialsMatch(token, account));
    }
}
