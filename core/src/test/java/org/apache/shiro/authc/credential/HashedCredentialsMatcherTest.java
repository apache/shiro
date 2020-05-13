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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Sha1Hash;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.lang.util.ByteSource;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * Tests for the {@link org.apache.shiro.authc.credential.HashedCredentialsMatcher} class.
 */
public class HashedCredentialsMatcherTest {

    /**
     * Test new Shiro 1.1 functionality, where the salt is obtained from the stored account information, as it
     * should be.  See <a href="https://issues.apache.org/jira/browse/SHIRO-186">SHIRO-186</a>
     */
    @Test
    public void testSaltedAuthenticationInfo() {
        //use SHA-1 hashing in this test:
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher(Sha1Hash.ALGORITHM_NAME);

        //simulate a user account with a SHA-1 hashed and salted password:
        ByteSource salt = new SecureRandomNumberGenerator().nextBytes();
        Object hashedPassword = new Sha1Hash("password", salt);
        SimpleAuthenticationInfo account = new SimpleAuthenticationInfo("username", hashedPassword, salt, "realmName");

        //simulate a username/password (plaintext) token created in response to a login attempt:
        AuthenticationToken token = new UsernamePasswordToken("username", "password");

        //verify the hashed token matches what is in the account:
        assertTrue(matcher.doCredentialsMatch(token, account));
    }

    /**
     * Test backwards compatibility of unsalted credentials before
     * <a href="https://issues.apache.org/jira/browse/SHIRO-186">SHIRO-186</a> edits.
     */
    @Test
    public void testBackwardsCompatibleUnsaltedAuthenticationInfo() {
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher(Sha1Hash.ALGORITHM_NAME);

        //simulate an account with SHA-1 hashed password (no salt)
        final String username = "username";
        final String password = "password";
        final Object hashedPassword = new Sha1Hash(password).getBytes();
        AuthenticationInfo account = new AuthenticationInfo() {
            public PrincipalCollection getPrincipals() {
                return new SimplePrincipalCollection(username, "realmName");
            }

            public Object getCredentials() {
                return hashedPassword;
            }
        };

        //simulate a username/password (plaintext) token created in response to a login attempt:
        AuthenticationToken token = new UsernamePasswordToken("username", "password");

        //verify the hashed token matches what is in the account:
        assertTrue(matcher.doCredentialsMatch(token, account));
    }

    /**
     * Test backwards compatibility of salted credentials before
     * <a href="https://issues.apache.org/jira/browse/SHIRO-186">SHIRO-186</a> edits.
     */
    @Test
    public void testBackwardsCompatibleSaltedAuthenticationInfo() {
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher(Sha1Hash.ALGORITHM_NAME);
        //enable this for Shiro 1.0 backwards compatibility:
        matcher.setHashSalted(true);

        //simulate an account with SHA-1 hashed password, using the username as the salt
        //(BAD IDEA, but backwards-compatible):
        final String username = "username";
        final String password = "password";
        final Object hashedPassword = new Sha1Hash(password, username).getBytes();
        AuthenticationInfo account = new AuthenticationInfo() {
            public PrincipalCollection getPrincipals() {
                return new SimplePrincipalCollection(username, "realmName");
            }

            public Object getCredentials() {
                return hashedPassword;
            }
        };

        //simulate a username/password (plaintext) token created in response to a login attempt:
        AuthenticationToken token = new UsernamePasswordToken("username", "password");

        //verify the hashed token matches what is in the account:
        assertTrue(matcher.doCredentialsMatch(token, account));
    }
}
