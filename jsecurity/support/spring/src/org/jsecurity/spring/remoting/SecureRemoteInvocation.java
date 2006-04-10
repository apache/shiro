package org.jsecurity.spring.remoting;

import org.aopalliance.intercept.MethodInvocation;
import org.jsecurity.session.Session;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;

/**
 * An extension of the Spring remoting {@link RemoteInvocation} that includes a
 * JSecurity session ID tying the remote invocation to a session on the server.
 *
 * <p>
 * A <tt>SecureRemoteInvocation</tt> will be created for each method invocation if
 * the {@link SecureRemoteInvocationFactory} is configured into the local proxies for
 * remote objects. (typically a subclass of
 * {@link org.springframework.remoting.support.RemoteInvocationBasedAccessor} )
 * </p>
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class SecureRemoteInvocation extends RemoteInvocation {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private Serializable sessionId;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public SecureRemoteInvocation(MethodInvocation methodInvocation, Session session) {
        this(methodInvocation, session.getSessionId());
    }

    public SecureRemoteInvocation(MethodInvocation methodInvocation, Serializable sessionId) {
        super(methodInvocation);
        this.sessionId = sessionId;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * The session ID of the user making the remote invocation.
     * @return the session ID for the remote invocation.
     */
    public Serializable getSessionId() {
        return sessionId;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
}
