/*
 * Copyright (C) 2005-2007 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.authc.support;

import static org.easymock.EasyMock.*;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.event.AuthenticationEventFactory;
import org.jsecurity.authc.event.FailedAuthenticationEvent;
import org.jsecurity.authc.event.SuccessfulAuthenticationEvent;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class AbstractAuthenticatorTest {

    AbstractAuthenticator abstractAuthenticator;
    private final SimpleAccount account = new SimpleAccount( "user1", "secret" );

    private AbstractAuthenticator createAuthcReturnNull() {
        return new AbstractAuthenticator() {
            protected Account doAuthenticate( AuthenticationToken token ) throws AuthenticationException {
                return null;
            }
        };
    }

    private AbstractAuthenticator createAuthcReturnValidAuthcInfo() {
        return new AbstractAuthenticator() {
            protected Account doAuthenticate( AuthenticationToken token ) throws AuthenticationException {
                return account;
            }
        };
    }

    private AuthenticationToken newToken() {
        return new UsernamePasswordToken( "user1", "secret".toCharArray() );
    }

    protected void initAuthc() {
        abstractAuthenticator.init();
    }

    @Before
    public void setUp() {
        abstractAuthenticator = createAuthcReturnValidAuthcInfo();
    }

    @Test
    public void newAbstractAuthenticatorSecurityManagerConstructor() {
        abstractAuthenticator = new AbstractAuthenticator() {
            protected Account doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                return account;
            }
        };
        initAuthc();
    }

    /**
     * Tests that the authenticate() method fails if the instance's init() method wasn't called.
     */
    @Test(expected=IllegalStateException.class)
    public void authenticateWithoutFirstCallingInit() {
        abstractAuthenticator.authenticate( newToken() );
    }

    /**
     * Ensures that the authenticate() method proactively fails if a <tt>null</tt> AuthenticationToken is passed as an
     * argument.
     */
    @Test(expected=IllegalArgumentException.class)
    public void authenticateWithNullArgument() {
        initAuthc();
        abstractAuthenticator.authenticate( null );
    }

    /**
     * Ensures that the authenticate() method throws an AuthenticationException if the subclass returns <tt>null</tt>
     * as the return value to the doAuthenticate() method.
     */
    @Test(expected=AuthenticationException.class)
    public void throwAuthenticationExceptionIfDoAuthenticateReturnsNull() {
        abstractAuthenticator = createAuthcReturnNull();
        initAuthc();
        abstractAuthenticator.authenticate( newToken() );
    }

    /**
     * Ensures a non-null <tt>Subject</tt> instance is returned from the authenticate() method after a valid
     * authentication attempt (i.e. the subclass's doAuthenticate implementation returns a valid, non-null
     * Account object).
     */
    @Test
    public void nonNullAccountAfterAuthenticate() {
        initAuthc();
        Account authcInfo = abstractAuthenticator.authenticate( newToken() );
        assertNotNull( authcInfo );
    }

    @Test(expected=AuthenticationException.class)
    public void createFailureEventReturnsNull() {
        abstractAuthenticator = new AbstractAuthenticator() {
            protected Account doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                throw new AuthenticationException();
            }
            protected AuthenticationEvent createFailureEvent(AuthenticationToken token, AuthenticationException ae) {
                return null;
            }
        };
        initAuthc();
        abstractAuthenticator.authenticate( newToken() );
    }

    @Test
    public void createSuccessEventReturnsNull() {
        abstractAuthenticator = new AbstractAuthenticator() {
            protected Account doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                return account;
            }
            protected AuthenticationEvent createSuccessEvent(AuthenticationToken token, Account account ) {
                return null;
            }
        };
        initAuthc();
        abstractAuthenticator.authenticate( newToken() );
    }

    @Test(expected=IllegalArgumentException.class)
    public void sendWithNullArgument() {
        initAuthc();
        abstractAuthenticator.send( null );
    }

    @Test
    public void sendWithSenderThrowingException() {
        AuthenticationEventFactory mockFactory = createMock( AuthenticationEventFactory.class );
        abstractAuthenticator.setAuthenticationEventFactory( mockFactory );
        initAuthc();
        AuthenticationToken token = newToken();
        SuccessfulAuthenticationEvent successEvent = new SuccessfulAuthenticationEvent( token, account );
        expect( mockFactory.createSuccessEvent( token, account) ).andReturn( successEvent );
        expectLastCall().andThrow( new RuntimeException() );
        replay( mockFactory );
        abstractAuthenticator.sendSuccessEvent( token, account);
        verify( mockFactory );
    }

    @Test(expected=AuthenticationException.class)
    public void sendWithSenderThrowingExceptionFailingAuthentication() {
        AuthenticationEventFactory mockFactory = createMock( AuthenticationEventFactory.class );
        abstractAuthenticator.setAuthenticationEventFactory( mockFactory );
        initAuthc();
        AuthenticationToken token = newToken();
        SuccessfulAuthenticationEvent successEvent = new SuccessfulAuthenticationEvent( token, account );
        expect( mockFactory.createSuccessEvent( token, account) ).andReturn( successEvent );
        expectLastCall().andThrow( new RuntimeException() );
        replay( mockFactory );
        abstractAuthenticator.sendSuccessEvent( token, account);
        verify( mockFactory );
    }

    @Test
    public void sendSuccessEventAfterDoAuthenticate() {
        AuthenticationEventFactory mockEvtFactory = createMock( AuthenticationEventFactory.class );

        abstractAuthenticator.setAuthenticationEventFactory( mockEvtFactory  );

        initAuthc();

        AuthenticationToken token = newToken();

        AuthenticationEvent successEvent = new SuccessfulAuthenticationEvent( token, account );

        expect( mockEvtFactory.createSuccessEvent( token, account) ).andReturn( successEvent );

        replay( mockEvtFactory );

        abstractAuthenticator.authenticate( token );

        verify( mockEvtFactory );
    }

    @Test
    public void sendFailedEventAfterDoAuthenticateThrowsAuthenticationException() {
        AuthenticationEventFactory mockEvtFactory = createMock( AuthenticationEventFactory.class );

        AuthenticationToken token = newToken();

        final AuthenticationException ae = new AuthenticationException( "dummy exception to test event sending" );
        final AuthenticationEvent failedEvent = new FailedAuthenticationEvent( token, ae );

        abstractAuthenticator = new AbstractAuthenticator() {
            protected Account doAuthenticate( AuthenticationToken token ) throws AuthenticationException {
                throw ae;
            }
        };

        abstractAuthenticator.setAuthenticationEventFactory( mockEvtFactory  );

        initAuthc();


        expect( mockEvtFactory.createFailureEvent( token, ae ) ).andReturn( failedEvent );


        replay( mockEvtFactory );

        boolean exceptionThrown = false;
        try {
            abstractAuthenticator.authenticate( token );
        } catch (AuthenticationException e) {
            exceptionThrown = true;
            assertEquals( e, ae );
        }
        verify( mockEvtFactory );

        if ( !exceptionThrown ) {
            fail( "An AuthenticationException should have been thrown during the sendFailedEvent test case." );
        }
    }

    @Test(expected=AuthenticationException.class)
    public void sendFailedEventAfterDoAuthenticateThrowsNonAuthenticationException() {

        abstractAuthenticator = new AbstractAuthenticator() {
            protected Account doAuthenticate( AuthenticationToken token ) throws AuthenticationException {
                throw new IllegalArgumentException( "not an AuthenticationException subclass" );
            }
        };

        initAuthc();

        AuthenticationToken token = newToken();

        abstractAuthenticator.authenticate( token );
    }

}
