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
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.UUID;

import static junit.framework.Assert.*;
import static org.easymock.EasyMock.*;

/**
 * Tests for the {@link JndiLdapContextFactory} class.
 *
 * @since 1.1
 */
public class JndiLdapContextFactoryTest {

    private JndiLdapContextFactory factory;

    @Before
    public void setUp() {
        factory = new JndiLdapContextFactory() {
            //Fake a JNDI environment for the tests:
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                return createNiceMock(LdapContext.class);
            }
        };
    }

    /**
     * This is the only test that does not fake the JNDI environment.  It is provided for 100% test coverage.
     *
     * @throws NamingException thrown because the host is always broken.
     */
    @Test(expected = NamingException.class)
    public void testGetLdapContext() throws NamingException {
        factory = new JndiLdapContextFactory();
        //garbage URL to test that the context is being created, but fails:
        String brokenHost = UUID.randomUUID().toString();
        factory.setUrl("ldap://" + brokenHost + ":389");
        factory.getLdapContext((Object) "foo", "bar");
    }

    @Test
    public void testAuthenticationMechanism() {
        String mech = "MD5-DIGEST";
        factory.setAuthenticationMechanism(mech);
        assertEquals(mech, factory.getAuthenticationMechanism());
    }

    @Test
    public void testReferral() {
        String referral = "throw";
        factory.setReferral(referral);
        assertEquals(referral, factory.getReferral());
    }

    @Test
    public void testGetContextFactoryClassName() {
        assertEquals(JndiLdapContextFactory.DEFAULT_CONTEXT_FACTORY_CLASS_NAME, factory.getContextFactoryClassName());
    }

    @Test
    public void testSetEnvironmentPropertyNull() {
        factory.setAuthenticationMechanism("MD5-DIGEST");
        factory.setAuthenticationMechanism(null);
        assertNull(factory.getAuthenticationMechanism());
    }

    @Test
    public void testCustomEnvironment() {
        Map<String, String> map = new HashMap<String, String>();
        map.put("foo", "bar");
        factory.setEnvironment(map);
        assertEquals("bar", factory.getEnvironment().get("foo"));
    }

    @Test(expected = IllegalStateException.class)
    public void testGetLdapContextWithoutUrl() throws NamingException {
        factory.getLdapContext((Object) "foo", "bar");
    }

    @Test
    public void testGetLdapContextDefault() throws NamingException {
        factory = new JndiLdapContextFactory() {
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                assertEquals("ldap://localhost:389", env.get(Context.PROVIDER_URL));
                assertEquals("foo", env.get(Context.SECURITY_PRINCIPAL));
                assertEquals("bar", env.get(Context.SECURITY_CREDENTIALS));
                assertEquals("simple", env.get(Context.SECURITY_AUTHENTICATION));
                assertNull(env.get(SUN_CONNECTION_POOLING_PROPERTY));
                return createNiceMock(LdapContext.class);
            }
        };

        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext((Object) "foo", "bar");
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void testGetLdapContextStringArguments() throws NamingException {
        factory = new JndiLdapContextFactory() {
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                assertEquals("ldap://localhost:389", env.get(Context.PROVIDER_URL));
                assertEquals("foo", env.get(Context.SECURITY_PRINCIPAL));
                assertEquals("bar", env.get(Context.SECURITY_CREDENTIALS));
                assertEquals("simple", env.get(Context.SECURITY_AUTHENTICATION));
                assertNull(env.get(SUN_CONNECTION_POOLING_PROPERTY));
                return createNiceMock(LdapContext.class);
            }
        };

        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext("foo", "bar");
    }

    @Test
    public void testGetSystemLdapContext() throws NamingException {
        factory = new JndiLdapContextFactory() {
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                assertEquals("ldap://localhost:389", env.get(Context.PROVIDER_URL));
                assertEquals("foo", env.get(Context.SECURITY_PRINCIPAL));
                assertEquals("bar", env.get(Context.SECURITY_CREDENTIALS));
                assertEquals("simple", env.get(Context.SECURITY_AUTHENTICATION));
                assertNotNull(env.get(SUN_CONNECTION_POOLING_PROPERTY));
                return createNiceMock(LdapContext.class);
            }
        };

        factory.setSystemUsername("foo");
        factory.setSystemPassword("bar");
        factory.setUrl("ldap://localhost:389");
        factory.getSystemLdapContext();
    }

    @Test
    public void testGetSystemLdapContextPoolingDisabled() throws NamingException {
        factory = new JndiLdapContextFactory() {
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                assertEquals("ldap://localhost:389", env.get(Context.PROVIDER_URL));
                assertEquals("foo", env.get(Context.SECURITY_PRINCIPAL));
                assertEquals("bar", env.get(Context.SECURITY_CREDENTIALS));
                assertEquals("simple", env.get(Context.SECURITY_AUTHENTICATION));
                assertNull(env.get(SUN_CONNECTION_POOLING_PROPERTY));
                return createNiceMock(LdapContext.class);
            }
        };

        factory.setSystemUsername("foo");
        factory.setSystemPassword("bar");
        factory.setPoolingEnabled(false);
        factory.setUrl("ldap://localhost:389");
        factory.getSystemLdapContext();
    }

    @Test(expected = AuthenticationException.class)
    public void testEmptyStringCredentials() throws NamingException {
        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext((Object)"jcoder", "");
    }

    @Test(expected = AuthenticationException.class)
    public void testEmptyCharArrayCredentials() throws NamingException {
        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext((Object)"jcoder", new char[0]);
    }

    @Test(expected = AuthenticationException.class)
    public void testEmptyByteArrayCredentials() throws NamingException {
        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext((Object)"jcoder", new byte[0]);
    }

    @Test(expected = AuthenticationException.class)
    public void testEmptyNullCredentials() throws NamingException {
        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext((Object)"jcoder", null);
    }



}
