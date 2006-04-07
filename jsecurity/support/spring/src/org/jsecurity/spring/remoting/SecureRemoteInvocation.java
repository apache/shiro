package org.jsecurity.spring.remoting;

import org.aopalliance.intercept.MethodInvocation;
import org.jsecurity.session.Session;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;

/**
 * Insert JavaDoc here.
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
        super(methodInvocation);
        if( session != null ) {
            this.sessionId = session.getSessionId();
        }
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public Serializable getSessionId() {
        return sessionId;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
}
