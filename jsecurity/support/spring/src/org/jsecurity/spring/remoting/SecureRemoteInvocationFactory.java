package org.jsecurity.spring.remoting;

import org.aopalliance.intercept.MethodInvocation;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;
import org.springframework.remoting.support.DefaultRemoteInvocationFactory;
import org.springframework.remoting.support.RemoteInvocation;

/**
 * Insert JavaDoc here.
 */
public class SecureRemoteInvocationFactory extends DefaultRemoteInvocationFactory {

    public RemoteInvocation createRemoteInvocation(MethodInvocation methodInvocation) {
        Session session = SecurityContext.getSession();
        return new SecureRemoteInvocation( methodInvocation, session );
    }
}
