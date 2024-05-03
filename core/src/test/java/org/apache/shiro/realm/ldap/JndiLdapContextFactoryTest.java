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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.easymock.EasyMock.createNiceMock;


/**
 * Tests for the {@link JndiLdapContextFactory} class.
 *
 * @since 1.1
 */
public class JndiLdapContextFactoryTest {

    private JndiLdapContextFactory factory;

    @BeforeEach
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
    @Test
    void testGetLdapContext() throws NamingException {
        assertThatExceptionOfType(NamingException.class).isThrownBy(() -> {
            factory = new JndiLdapContextFactory();
            //garbage URL to test that the context is being created, but fails:
            String brokenHost = UUID.randomUUID().toString();
            factory.setUrl("ldap://" + brokenHost + ":389");
            factory.getLdapContext("foo", "bar");
        });
    }

    @Test
    void testAuthenticationMechanism() {
        String mech = "MD5-DIGEST";
        factory.setAuthenticationMechanism(mech);
        assertThat(factory.getAuthenticationMechanism()).isEqualTo(mech);
    }

    @Test
    void testReferral() {
        String referral = "throw";
        factory.setReferral(referral);
        assertThat(factory.getReferral()).isEqualTo(referral);
    }

    @Test
    void testGetContextFactoryClassName() {
        assertThat(factory.getContextFactoryClassName()).isEqualTo(JndiLdapContextFactory.DEFAULT_CONTEXT_FACTORY_CLASS_NAME);
    }

    @Test
    void testSetEnvironmentPropertyNull() {
        factory.setAuthenticationMechanism("MD5-DIGEST");
        factory.setAuthenticationMechanism(null);
        assertThat(factory.getAuthenticationMechanism()).isNull();
    }

    @Test
    void testCustomEnvironment() {
        Map<String, String> map = new HashMap<String, String>();
        map.put("foo", "bar");
        factory.setEnvironment(map);
        assertThat(factory.getEnvironment()).containsEntry("foo", "bar");
    }

    @Test
    void testGetLdapContextWithoutUrl() throws NamingException {
        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> {
            factory.getLdapContext("foo", "bar");
        });
    }

    @Test
    void testGetLdapContextDefault() throws NamingException {
        factory = new JndiLdapContextFactory() {
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                assertThat(env).containsEntry(Context.PROVIDER_URL, "ldap://localhost:389");
                assertThat(env).containsEntry(Context.SECURITY_PRINCIPAL, "foo");
                assertThat(env).containsEntry(Context.SECURITY_CREDENTIALS, "bar");
                assertThat(env).containsEntry(Context.SECURITY_AUTHENTICATION, "simple");
                assertThat(env.get(SUN_CONNECTION_POOLING_PROPERTY)).isNull();
                return createNiceMock(LdapContext.class);
            }
        };

        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext("foo", "bar");
    }

    @SuppressWarnings({"deprecation"})
    @Test
    void testGetLdapContextStringArguments() throws NamingException {
        factory = new JndiLdapContextFactory() {
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                assertThat(env).containsEntry(Context.PROVIDER_URL, "ldap://localhost:389");
                assertThat(env).containsEntry(Context.SECURITY_PRINCIPAL, "foo");
                assertThat(env).containsEntry(Context.SECURITY_CREDENTIALS, "bar");
                assertThat(env).containsEntry(Context.SECURITY_AUTHENTICATION, "simple");
                assertThat(env.get(SUN_CONNECTION_POOLING_PROPERTY)).isNull();
                return createNiceMock(LdapContext.class);
            }
        };

        factory.setUrl("ldap://localhost:389");
        factory.getLdapContext("foo", "bar");
    }

    @Test
    void testGetSystemLdapContext() throws NamingException {
        factory = new JndiLdapContextFactory() {
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                assertThat(env).containsEntry(Context.PROVIDER_URL, "ldap://localhost:389");
                assertThat(env).containsEntry(Context.SECURITY_PRINCIPAL, "foo");
                assertThat(env).containsEntry(Context.SECURITY_CREDENTIALS, "bar");
                assertThat(env).containsEntry(Context.SECURITY_AUTHENTICATION, "simple");
                assertThat(env.get(SUN_CONNECTION_POOLING_PROPERTY)).isNotNull();
                return createNiceMock(LdapContext.class);
            }
        };

        factory.setSystemUsername("foo");
        factory.setSystemPassword("bar");
        factory.setUrl("ldap://localhost:389");
        factory.getSystemLdapContext();
    }

    @Test
    void testGetSystemLdapContextPoolingDisabled() throws NamingException {
        factory = new JndiLdapContextFactory() {
            @Override
            protected LdapContext createLdapContext(Hashtable env) throws NamingException {
                assertThat(env).containsEntry(Context.PROVIDER_URL, "ldap://localhost:389");
                assertThat(env).containsEntry(Context.SECURITY_PRINCIPAL, "foo");
                assertThat(env).containsEntry(Context.SECURITY_CREDENTIALS, "bar");
                assertThat(env).containsEntry(Context.SECURITY_AUTHENTICATION, "simple");
                assertThat(env.get(SUN_CONNECTION_POOLING_PROPERTY)).isNull();
                return createNiceMock(LdapContext.class);
            }
        };

        factory.setSystemUsername("foo");
        factory.setSystemPassword("bar");
        factory.setPoolingEnabled(false);
        factory.setUrl("ldap://localhost:389");
        factory.getSystemLdapContext();
    }

    @Test
    void testEmptyStringCredentials() throws NamingException {
        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(() -> {
            factory.setUrl("ldap://localhost:389");
            factory.getLdapContext("jcoder", "");
        });
    }

    @Test
    void testEmptyCharArrayCredentials() throws NamingException {
        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(() -> {
            factory.setUrl("ldap://localhost:389");
            factory.getLdapContext("jcoder", new char[0]);
        });
    }

    @Test
    void testEmptyByteArrayCredentials() throws NamingException {
        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(() -> {
            factory.setUrl("ldap://localhost:389");
            factory.getLdapContext("jcoder", new byte[0]);
        });
    }

    @Test
    void testEmptyNullCredentials() throws NamingException {
        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(() -> {
            factory.setUrl("ldap://localhost:389");
            factory.getLdapContext("jcoder", null);
        });
    }


}
