package org.jsecurity.spring.remoting;

import org.aopalliance.intercept.MethodInvocation;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;
import org.springframework.remoting.support.DefaultRemoteInvocationFactory;
import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.remoting.support.RemoteInvocationFactory;

import java.io.Serializable;
import java.util.UUID;

/**
 * A {@link RemoteInvocationFactory} that passes the session ID to the server via a
 * {@link SecureRemoteInvocation} instance.  This factory is the client-side part of
 * the JSecurity Spring remoting invocation.  A {@link SecureRemoteInvocationExecutor} should
 * be used to export the server-side remote services to ensure that the appropriate session
 * and authorization context is bound to the remote thread during execution.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class SecureRemoteInvocationFactory extends DefaultRemoteInvocationFactory {

    /**
     * Creates a {@link SecureRemoteInvocation} based on the current session or session
     * ID.
     * @param methodInvocation the method invocation that the remote invocation should
     * be based on.
     * @return a remote invocation object containing the current session ID.
     */
    public RemoteInvocation createRemoteInvocation(MethodInvocation methodInvocation) {
        Session session = SecurityContext.getSession();

        Serializable sessionId;
        if( session != null ) {
            sessionId = session.getSessionId();
        } else {
            sessionId = UUID.fromString( System.getProperty( "jsecurity.session.id" ) );
        }

        if( sessionId != null ) {
            return new SecureRemoteInvocation( methodInvocation, sessionId );
        } else {
            return super.createRemoteInvocation( methodInvocation );
        }

    }
}
