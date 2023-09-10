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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import java.util.UUID;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.hamcrest.Matchers.isA;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;


/**
 * Tests for the {@link DefaultLdapRealm} class.
 *
 * @since 1.3
 */
@SuppressWarnings({"ThrowableInstanceNeverThrown"})
public class DefaultLdapRealmTest {

    private DefaultLdapRealm realm;

    // this method can be collapsed back into setUp once the JndiLdapRealm has been removed in 2.0
    protected DefaultLdapRealm getNewRealmUnderTest() {
        return new DefaultLdapRealm();
    }

    @BeforeEach
    public void setUp() {
        realm = getNewRealmUnderTest();
    }

    @Test
    void testDefaultInstance() {
        assertTrue(realm.getCredentialsMatcher() instanceof AllowAllCredentialsMatcher);
        assertEquals(AuthenticationToken.class, realm.getAuthenticationTokenClass());
        assertTrue(realm.getContextFactory() instanceof JndiLdapContextFactory);
    }

    @Test
    void testSetUserDnTemplateNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            realm.setUserDnTemplate(null);
        });
    }

    @Test
    void testSetUserDnTemplateEmpty() {
        assertThrows(IllegalArgumentException.class, () -> {
            realm.setUserDnTemplate("  ");
        });
    }

    @Test
    void testSetUserDnTemplateWithoutToken() {
        assertThrows(IllegalArgumentException.class, () -> {
            realm.setUserDnTemplate("uid=,ou=users,dc=mycompany,dc=com");
        });
    }

    @Test
    void testUserDnTemplate() {
        String template = "uid={0},ou=users,dc=mycompany,dc=com";
        realm.setUserDnTemplate(template);
        assertEquals(template, realm.getUserDnTemplate());
    }

    @Test
    void testUserDnTemplateSubstitution() throws NamingException {
        realm.setUserDnTemplate("uid={0},ou=users,dc=mycompany,dc=com");
        LdapContextFactory factory = createMock(LdapContextFactory.class);
        realm.setContextFactory(factory);

        Object expectedPrincipal = "uid=jsmith,ou=users,dc=mycompany,dc=com";

        expect(factory.getLdapContext(eq(expectedPrincipal), isA(Object.class)))
                .andReturn(createNiceMock(LdapContext.class));
        replay(factory);

        realm.getAuthenticationInfo(new UsernamePasswordToken("jsmith", "secret"));
        verify(factory);
    }

    @Test
    void testGetAuthenticationInfoNamingAuthenticationException() throws NamingException {
        assertThrows(AuthenticationException.class, () -> {
            realm.setUserDnTemplate("uid={0},ou=users,dc=mycompany,dc=com");
            LdapContextFactory factory = createMock(LdapContextFactory.class);
            realm.setContextFactory(factory);

            expect(factory.getLdapContext(isA(Object.class), isA(Object.class)))
                    .andThrow(new javax.naming.AuthenticationException("LDAP Authentication failed."));
            replay(factory);

            realm.getAuthenticationInfo(new UsernamePasswordToken("jsmith", "secret"));
        });
    }

    @Test
    void testGetAuthenticationInfoNamingException() throws NamingException {
        assertThrows(AuthenticationException.class, () -> {
            realm.setUserDnTemplate("uid={0},ou=users,dc=mycompany,dc=com");
            LdapContextFactory factory = createMock(LdapContextFactory.class);
            realm.setContextFactory(factory);

            expect(factory.getLdapContext(isA(Object.class), isA(Object.class)))
                    .andThrow(new NamingException("Communication error."));
            replay(factory);

            realm.getAuthenticationInfo(new UsernamePasswordToken("jsmith", "secret"));
        });
    }

    /**
     * This test simulates that if a non-String principal (i.e. not a username) is passed as the LDAP principal, that
     * it is not altered into a User DN and is passed as-is.  This will allow principals to be things like X.509
     * certificates as well instead of only strings.
     *
     * @throws NamingException not thrown
     */
    @Test
    void testGetAuthenticationInfoNonSimpleToken() throws NamingException {
        realm.setUserDnTemplate("uid={0},ou=users,dc=mycompany,dc=com");
        LdapContextFactory factory = createMock(LdapContextFactory.class);
        realm.setContextFactory(factory);

        final UUID userId = UUID.randomUUID();

        //ensure the userId is passed as-is:
        expect(factory.getLdapContext(eq(userId), isA(Object.class))).andReturn(createNiceMock(LdapContext.class));
        replay(factory);

        realm.getAuthenticationInfo(new AuthenticationToken() {
            public Object getPrincipal() {
                return userId;
            }

            public Object getCredentials() {
                return "secret";
            }
        });
        verify(factory);
    }

    @Test
    void testGetUserDnNullArgument() {
        assertThrows(IllegalArgumentException.class, () -> {
            realm.getUserDn(null);
        });
    }

    @Test
    void testGetUserDnWithOutPrefixAndSuffix() {
        realm = new DefaultLdapRealm() {
            @Override
            protected String getUserDnPrefix() {
                return null;
            }

            @Override
            protected String getUserDnSuffix() {
                return null;
            }
        };
        String principal = "foo";
        String userDn = realm.getUserDn(principal);
        assertEquals(principal, userDn);
    }
}
