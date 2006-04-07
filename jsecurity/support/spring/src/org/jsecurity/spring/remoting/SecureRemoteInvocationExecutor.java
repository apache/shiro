package org.jsecurity.spring.remoting;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.ri.util.ThreadUtils;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.springframework.remoting.support.DefaultRemoteInvocationExecutor;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;

/**
 * Insert JavaDoc here.
 */
public class SecureRemoteInvocationExecutor extends DefaultRemoteInvocationExecutor {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logger.
     */
    protected transient final Log log = LogFactory.getLog( getClass() );

    /**
     * Session factory used to create/retrieve sessions that are specified in
     * remote requests.
     */
    private SessionFactory sessionFactory;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public Object invoke(RemoteInvocation invocation, Object targetObject) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {

        if( invocation instanceof SecureRemoteInvocation ) {
            SecureRemoteInvocation secureInvocation = (SecureRemoteInvocation) invocation;

            Serializable sessionId = secureInvocation.getSessionId();
            Session session = sessionFactory.getSession( sessionId );
            ThreadUtils.bindToThread( session );

        } else {
            if( log.isWarnEnabled() ) {
                log.warn( "Secure remote invocation executor used, but did not receive a " +
                        "SecureRemoteInvocation from remote call.  Session will not be propogated to the remote invocation.  " +
                        "Ensure that clients are using a SecureRemoteInvocationFactory to prevent this problem." );
            }
        }

        try {
            return super.invoke(invocation, targetObject);
        } finally {
            ThreadUtils.unbindSessionFromThread();
        }
    }
}
