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

import org.apache.logging.log4j.junit.LoggerContextRule;
import org.apache.logging.log4j.test.appender.ListAppender;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * @since 0.1
 */
public class AbstractAuthenticatorTest {

    @ClassRule
    public static LoggerContextRule loggerContextRule = new LoggerContextRule("log4j2-list.xml");

    AbstractAuthenticator abstractAuthenticator;
    private final SimpleAuthenticationInfo info = new SimpleAuthenticationInfo("user1", "secret", "realmName");

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

    @Before
    public void setUp() {
        abstractAuthenticator = createAuthcReturnValidAuthcInfo();
    }

    @Test
    public void newAbstractAuthenticatorSecurityManagerConstructor() {
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
    @Test(expected = IllegalArgumentException.class)
    public void authenticateWithNullArgument() {
        abstractAuthenticator.authenticate(null);
    }

    /**
     * Ensures that the authenticate() method throws an AuthenticationException if the subclass returns <tt>null</tt>
     * as the return value to the doAuthenticate() method.
     */
    @Test(expected = AuthenticationException.class)
    public void throwAuthenticationExceptionIfDoAuthenticateReturnsNull() {
        abstractAuthenticator = createAuthcReturnNull();
        abstractAuthenticator.authenticate(newToken());
    }

    /**
     * Ensures a non-null <tt>Subject</tt> instance is returned from the authenticate() method after a valid
     * authentication attempt (i.e. the subclass's doAuthenticate implementation returns a valid, non-null
     * AuthenticationInfo object).
     */
    @Test
    public void nonNullAuthenticationInfoAfterAuthenticate() {
        AuthenticationInfo authcInfo = abstractAuthenticator.authenticate(newToken());
        assertNotNull(authcInfo);
    }

    @Test
    public void notifySuccessAfterDoAuthenticate() {
        AuthenticationListener mockListener = createMock(AuthenticationListener.class);
        abstractAuthenticator.getAuthenticationListeners().add(mockListener);
        AuthenticationToken token = newToken();
        mockListener.onSuccess(token, info);

        replay(mockListener);
        abstractAuthenticator.authenticate(token);
        verify(mockListener);
    }

    @Test
    public void notifyFailureAfterDoAuthenticateThrowsAuthenticationException() {
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

    @Test(expected = AuthenticationException.class)
    public void notifyFailureAfterDoAuthenticateThrowsNonAuthenticationException() {
        abstractAuthenticator = new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                throw new IllegalArgumentException("not an AuthenticationException subclass");
            }
        };
        AuthenticationToken token = newToken();
        abstractAuthenticator.authenticate(token);
    }

    @Test
    public void logExceptionAfterDoAuthenticateThrowsNonAuthenticationException() {
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

        final ListAppender listAppender = loggerContextRule.getListAppender("List");
        String logMsg = String.join("\n", listAppender.getMessages());
        assertTrue(logMsg.contains("WARN"));
        assertTrue(logMsg.contains("java.lang.IllegalArgumentException: "+ expectedExceptionMessage));
    }

}
