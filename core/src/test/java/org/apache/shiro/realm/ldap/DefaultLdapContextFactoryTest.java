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
package org.apache.shiro.realm.ldap;

import org.junit.Before;
import org.junit.Test;

import javax.naming.AuthenticationException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import java.util.Hashtable;
import java.util.UUID;

import static org.easymock.EasyMock.createNiceMock;

/**
 * Tests for the {@link org.apache.shiro.realm.ldap.DefaultLdapContextFactory} class.
 *
 * @since 1.2
 */
public class DefaultLdapContextFactoryTest
{

    private DefaultLdapContextFactory factory;

    @Before
    public void setUp() {
        factory = new DefaultLdapContextFactory() {
            //Fake a JNDI DefaultLdapContextFactory for the tests:
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                return createNiceMock(LdapContext.class);
            }
        };
    }

    /**
     * This is the only test that does not fake the JNDI environment.  It is provided for 100% test coverage.
     *
     * @throws javax.naming.NamingException thrown because the host is always broken.
     */
    @Test(expected = NamingException.class)
    public void testGetLdapContext() throws NamingException {
        factory = new DefaultLdapContextFactory();
        //garbage URL to test that the context is being created, but fails:
        String brokenHost = UUID.randomUUID().toString();
        factory.setUrl("ldap://" + brokenHost + ":389");
        factory.getLdapContext("foo", "bar");
    }

    @Test(expected = IllegalStateException.class)
    public void testGetLdapContextWithoutUrl() throws NamingException {
        factory.getLdapContext("foo", "bar");
    }





    @Test(expected = AuthenticationException.class)
    public void testEmptyStringCredentials() throws NamingException {
        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext("jcoder", "");
    }

    @Test(expected = AuthenticationException.class)
    public void testEmptyCharArrayCredentials() throws NamingException {
        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext("jcoder", new char[0]);
    }

    @Test(expected = AuthenticationException.class)
    public void testEmptyByteArrayCredentials() throws NamingException {
        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext("jcoder", new byte[0]);
    }

    @Test(expected = AuthenticationException.class)
    public void testEmptyNullCredentials() throws NamingException {
        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext("jcoder", null);
    }



}
