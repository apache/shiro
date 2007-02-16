package org.jsecurity.authc.support;

import static org.easymock.EasyMock.*;
import org.jsecurity.SecurityManager;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.event.*;
import org.jsecurity.authc.event.support.SimpleAuthenticationEventSender;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.bind.SecurityContextBinder;
import org.jsecurity.context.factory.SecurityContextFactory;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.util.UsernamePrincipal;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class AbstractAuthenticatorTest {

    AbstractAuthenticator abstractAuthenticator;
    SecurityManager mockSecurityManager;

    private final SimpleAuthenticationInfo authInfo =
            new SimpleAuthenticationInfo( new UsernamePrincipal( "user1" ), "secret" );

    private AbstractAuthenticator createAuthcReturnNull() {
        return new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate( AuthenticationToken token ) throws AuthenticationException {
                return null;
            }
        };
    }

    private AbstractAuthenticator createAuthcReturnValidAuthcInfo() {
        return new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate( AuthenticationToken token ) throws AuthenticationException {
                return authInfo;
            }
        };
    }

    private AuthenticationToken newToken() {
        return new UsernamePasswordToken( "user1", "secret".toCharArray() );
    }

    @Before
    public void setUp() {
        abstractAuthenticator = createAuthcReturnValidAuthcInfo();
        mockSecurityManager = createMock( SecurityManager.class );
    }

    /**
     * Asserts that if neither a SecurityContextFactory or a SessionManager have been set and init() is called, that
     * an exception is thrown due to the instance not being in an intializable state.
     */
    @Test(expected=IllegalStateException.class)
    public void initNoSessionFactoryNoSecurityManager() {
        assertNotNull( abstractAuthenticator.getSecurityContextBinder() ); //default impl set when instance created
        assertNotNull( abstractAuthenticator.getAuthenticationEventFactory() ); //default impl set when instance created
        abstractAuthenticator.init();
    }

    /**
     * Asserts that when the init() method is called without a SecurityContextFactory being set as a class attribute,
     * a SecurityContextFactory is lazily created (based on a previously injected SecurityManager) and non-null.
     */
    @Test
    public void initNoSessionFactory() {
        abstractAuthenticator.setSecurityManager( mockSecurityManager );
        abstractAuthenticator.init();
        assertNotNull( abstractAuthenticator.getSecurityContextBinder() ); //default impl set when instance created
        assertNotNull( abstractAuthenticator.getAuthenticationEventFactory() ); //default impl set when instance created
        assertNotNull( "After setting a SecurityManager and calling init() on AbstractAuthenticator, a " +
                "SecurityContextFactory instance should be implicitly created.",
                abstractAuthenticator.getSecurityContextFactory() );
    }

    protected void initAuthc() {
        abstractAuthenticator.setSecurityManager( mockSecurityManager );
        abstractAuthenticator.init();
    }

    /**
     * Tests that the authenticate() method fails if the instance's init() method wasn't called.
     */
    @Test(expected=IllegalStateException.class)
    public void authenticateNoInit() {
        abstractAuthenticator.authenticate( newToken() );
    }

    /**
     * Ensures that the authenticate() method proactively fails if a <tt>null</tt> AuthenticationToken is passed as an
     * argument.
     */
    @Test(expected=IllegalArgumentException.class)
    public void authenticateNullAgument() {
        initAuthc();
        abstractAuthenticator.authenticate( null );
    }

    /**
     * Ensures that the authenticate() method throws an AuthenticationException if the subclass returns <tt>null</tt>
     * as the return value to the doAuthenticate() method.
     */
    @Test(expected=AuthenticationException.class)
    public void authenticateSubclassDoAuthenticateReturnNull() {
        abstractAuthenticator = createAuthcReturnNull();
        initAuthc();
        abstractAuthenticator.authenticate( newToken() );
    }

    /**
     * Ensures a non-null <tt>SecurityContext</tt> instance is returned from the authenticate() method after a valid
     * authentication attempt (i.e. the subclass's doAuthenticate implementation returns a valid, non-null
     * AuthenticationInfo object).
     */
    @Test
    public void authenticateSuccessful() {
        initAuthc();
        SecurityContext securityContext = abstractAuthenticator.authenticate( newToken() );
        assertNotNull( securityContext );
    }

    /**
     * Asserts that whatever <tt>SecurityContextFactory</tt> is in use by the Authenticator (either default or
     * explicitly injected) does not return a null SecurityContext during the authentication phase.
     */
    @Test(expected=IllegalStateException.class)
    public void authenticateReturnedContextFactoryNull() {
        SecurityContextFactory mockSCF = createMock( SecurityContextFactory.class );
        abstractAuthenticator.setSecurityContextFactory( mockSCF );
        expect( mockSCF.createSecurityContext( authInfo ) ).andReturn( null );
        replay( mockSCF );
        initAuthc();
        abstractAuthenticator.authenticate( newToken() );

        verify( mockSCF );
    }

    /**
     * Asserts that the AbstractAuthenticator properly calls the <tt>SecurityContextBinder</tt> during a successful
     * authentication attempt.
     */
    @Test
    public void authenticateBindSecurityContext() {
        SecurityContextBinder mockBinder = createMock( SecurityContextBinder.class );
        SecurityContextFactory mockFactory = createMock( SecurityContextFactory.class );

        abstractAuthenticator.setSecurityContextBinder( mockBinder );
        abstractAuthenticator.setSecurityContextFactory( mockFactory );

        initAuthc();

        SecurityContext sc = new DelegatingSecurityContext( new UsernamePrincipal( "user1" ), mockSecurityManager );

        expect( mockFactory.createSecurityContext( authInfo ) ).andReturn( sc );

        //this is the test method's purpose: to ensure the following call on the binder is made by the authenticator:
        mockBinder.bindSecurityContext( sc );

        replay( mockFactory );
        replay( mockBinder );

        abstractAuthenticator.authenticate( newToken() );

        verify( mockFactory );
        verify( mockBinder );
    }

    @Test
    public void authenticateSuccessfulSendSuccessEvent() {
        AuthenticationEventSender mockAuthcEvtSender = createMock( AuthenticationEventSender.class );
        AuthenticationEventFactory mockEvtFactory = createMock( AuthenticationEventFactory.class );

        abstractAuthenticator.setAuthenticationEventSender( mockAuthcEvtSender );
        abstractAuthenticator.setAuthenticationEventFactory( mockEvtFactory  );

        initAuthc();

        AuthenticationToken token = newToken();

        AuthenticationEvent successEvent = new SuccessfulAuthenticationEvent( authInfo.getPrincipal() );

        expect( mockEvtFactory.createSuccessEvent( token, authInfo ) ).andReturn( successEvent );
        mockAuthcEvtSender.send( successEvent );

        replay( mockEvtFactory );
        replay( mockAuthcEvtSender );

        abstractAuthenticator.authenticate( token );

        verify( mockEvtFactory );
        verify( mockAuthcEvtSender );
    }

    @Test
    public void authenticateFailedSendFailedEvent() {
        AuthenticationEventSender mockAuthcEvtSender = createMock( AuthenticationEventSender.class );
        AuthenticationEventFactory mockEvtFactory = createMock( AuthenticationEventFactory.class );

        final AuthenticationException ae = new AuthenticationException( "dummy exception to test event sending" );
        final AuthenticationEvent failedEvent = new FailedAuthenticationEvent( authInfo.getPrincipal(), ae );


        abstractAuthenticator = new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate( AuthenticationToken token ) throws AuthenticationException {
                throw ae;
            }
        };

        abstractAuthenticator.setAuthenticationEventSender( mockAuthcEvtSender );
        abstractAuthenticator.setAuthenticationEventFactory( mockEvtFactory  );

        initAuthc();

        AuthenticationToken token = newToken();

        expect( mockEvtFactory.createFailureEvent( token, ae ) ).andReturn( failedEvent );

        mockAuthcEvtSender.send( failedEvent );

        replay( mockEvtFactory );
        replay( mockAuthcEvtSender );

        boolean exceptionThrown = false;
        try {
            abstractAuthenticator.authenticate( token );
        } catch (AuthenticationException e) {
            exceptionThrown = true;
            assertEquals( e, ae );
        }
        verify( mockAuthcEvtSender );
        verify( mockEvtFactory );

        if ( !exceptionThrown ) {
            fail( "An AuthenticationException should have been thrown during the sendFailedEvent test case." );
        }
    }

    @Test(expected=AuthenticationException.class)
    public void authenticateFailedNotAuthenticationExceptionSubclassSendFailedEvent() {

        AuthenticationEventSender dummyAuthcEvtSender = new SimpleAuthenticationEventSender();

        abstractAuthenticator = new AbstractAuthenticator() {
            protected AuthenticationInfo doAuthenticate( AuthenticationToken token ) throws AuthenticationException {
                throw new IllegalArgumentException( "not an AuthenticationException subclass" );
            }
        };

        abstractAuthenticator.setAuthenticationEventSender( dummyAuthcEvtSender );

        initAuthc();

        AuthenticationToken token = newToken();

        abstractAuthenticator.authenticate( token );
    }

}
