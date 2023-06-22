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
package org.apache.shiro.authc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.test.appender.ListAppender;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.jupiter.api.Assertions.*;


/**
 * @since 0.1
 */
public class AbstractAuthenticatorTest {

    static ListAppender listAppender;

    AbstractAuthenticator abstractAuthenticator;
    private final SimpleAuthenticationInfo info = new SimpleAuthenticationInfo("user1", "secret", "realmName");

    @BeforeAll
    static void setUpLogger() {
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(AbstractAuthenticatorTest.class.getClassLoader(), false, URI.create("log4j2-list.xml"));
        Configuration configuration = loggerContext.getConfiguration();
        listAppender = configuration.getAppender("List");
    }

    private AbstractAuthenticator createAuthcReturnNull() {
        return new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                return null;
            }
        };
    }

    private AbstractAuthenticator createAuthcReturnValidAuthcInfo() {
        return new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                return info;
            }
        };
    }

    private AuthenticationToken newToken() {
        return new UsernamePasswordToken("user1", "secret");
    }

    @BeforeEach
    public void setUp() {
        abstractAuthenticator = createAuthcReturnValidAuthcInfo();
    }

    @Test
    void newAbstractAuthenticatorSecurityManagerConstructor() {
        abstractAuthenticator = new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                return info;
            }
        };
    }


    /**
     * Ensures that the authenticate() method proactively fails if a <tt>null</tt> AuthenticationToken is passed as an
     * argument.
     */
    @Test
    void authenticateWithNullArgument() {
        assertThrows(IllegalArgumentException.class, () -> {
            abstractAuthenticator.authenticate(null);
        });
    }

    /**
     * Ensures that the authenticate() method throws an AuthenticationException if the subclass returns <tt>null</tt>
     * as the return value to the doAuthenticate() method.
     */
    @Test
    void throwAuthenticationExceptionIfDoAuthenticateReturnsNull() {
        assertThrows(AuthenticationException.class, () -> {
            abstractAuthenticator = createAuthcReturnNull();
            abstractAuthenticator.authenticate(newToken());
        });
    }

    /**
     * Ensures a non-null <tt>Subject</tt> instance is returned from the authenticate() method after a valid
     * authentication attempt (i.e. the subclass's doAuthenticate implementation returns a valid, non-null
     * AuthenticationInfo object).
     */
    @Test
    void nonNullAuthenticationInfoAfterAuthenticate() {
        AuthenticationInfo authcInfo = abstractAuthenticator.authenticate(newToken());
        assertNotNull(authcInfo);
    }

    @Test
    void notifySuccessAfterDoAuthenticate() {
        AuthenticationListener mockListener = createMock(AuthenticationListener.class);
        abstractAuthenticator.getAuthenticationListeners().add(mockListener);
        AuthenticationToken token = newToken();
        mockListener.onSuccess(token, info);

        replay(mockListener);
        abstractAuthenticator.authenticate(token);
        verify(mockListener);
    }

    @Test
    void notifyFailureAfterDoAuthenticateThrowsAuthenticationException() {
        AuthenticationListener mockListener = createMock(AuthenticationListener.class);
        AuthenticationToken token = newToken();

        final AuthenticationException ae = new AuthenticationException("dummy exception to test notification");

        abstractAuthenticator = new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                throw ae;
            }
        };
        abstractAuthenticator.getAuthenticationListeners().add(mockListener);

        mockListener.onFailure(token, ae);
        replay(mockListener);

        boolean exceptionThrown = false;
        try {
            abstractAuthenticator.authenticate(token);
        } catch (AuthenticationException e) {
            exceptionThrown = true;
            assertEquals(e, ae);
        }
        verify(mockListener);

        if (!exceptionThrown) {
            fail("An AuthenticationException should have been thrown during the notifyFailure test case.");
        }
    }

    @Test
    void notifyFailureAfterDoAuthenticateThrowsNonAuthenticationException() {
        assertThrows(AuthenticationException.class, () -> {
            abstractAuthenticator = new AbstractAuthenticator() {
                protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                    throw new IllegalArgumentException("not an AuthenticationException subclass");
                }
            };
            AuthenticationToken token = newToken();
            abstractAuthenticator.authenticate(token);
        });
    }

    @Test
    void logExceptionAfterDoAuthenticateThrowsNonAuthenticationException() {
        // NOTE: log4j is a test dependency
        final String expectedExceptionMessage = "exception thrown for test logExceptionAfterDoAuthenticateThrowsNonAuthenticationException";

        abstractAuthenticator = new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                throw new IllegalArgumentException(expectedExceptionMessage);
            }
        };
        AuthenticationToken token = newToken();

        try{
            abstractAuthenticator.authenticate(token);
            fail("the expected AuthenticationException was not thrown");
        }catch(AuthenticationException expectedException){
        }

        String logMsg = String.join("\n", listAppender.getMessages());
        assertTrue(logMsg.contains("WARN"));
        assertTrue(logMsg.contains("java.lang.IllegalArgumentException: "+ expectedExceptionMessage));
    }

}
