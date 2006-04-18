package org.jsecurity.spring.remoting;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.ri.util.ThreadUtils;
import org.jsecurity.ri.web.WebUtils;
import org.jsecurity.ri.authz.DelegatingAuthorizationContext;
import org.jsecurity.ri.authz.Realm;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.springframework.remoting.support.DefaultRemoteInvocationExecutor;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.security.Principal;
import java.util.List;

/**
 * An implementation of the Spring {@link org.springframework.remoting.support.RemoteInvocationExecutor}
 * that binds the correct {@link Session} and {@link org.jsecurity.authz.AuthorizationContext} to the
 * remote invocation thread during a remote execution.
 *
 * @since 0.1
 * @author Jeremy Haile
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

    private Realm realm;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public Object invoke(RemoteInvocation invocation, Object targetObject) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {

        try {

            if( invocation instanceof SecureRemoteInvocation ) {
                SecureRemoteInvocation secureInvocation = (SecureRemoteInvocation) invocation;

                Serializable sessionId = secureInvocation.getSessionId();
                Session session = sessionFactory.getSession( sessionId );
                ThreadUtils.bindToThread( session );

                List<Principal>principals = (List<Principal>) session.getAttribute( WebUtils.PRINCIPALS_SESSION_KEY );
                if( principals != null && !principals.isEmpty() ) {
                    ThreadUtils.bindToThread( new DelegatingAuthorizationContext( principals, realm ) );
                }

            } else {
                if( log.isWarnEnabled() ) {
                    log.warn( "Secure remote invocation executor used, but did not receive a " +
                            "SecureRemoteInvocation from remote call.  Session will not be propogated to the remote invocation.  " +
                            "Ensure that clients are using a SecureRemoteInvocationFactory to prevent this problem." );
                }
            }

            return super.invoke(invocation, targetObject);
        } finally {
            ThreadUtils.unbindSessionFromThread();
        }
    }
}
