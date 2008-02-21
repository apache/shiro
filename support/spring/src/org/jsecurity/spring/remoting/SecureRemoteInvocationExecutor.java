/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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
package org.jsecurity.spring.remoting;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityManager;
import org.jsecurity.session.Session;
import org.jsecurity.subject.DelegatingSubject;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.DefaultWebSecurityManager;
import org.springframework.remoting.support.DefaultRemoteInvocationExecutor;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/**
 * An implementation of the Spring {@link org.springframework.remoting.support.RemoteInvocationExecutor}
 * that binds the correct {@link Session} and {@link org.jsecurity.subject.Subject} to the
 * remote invocation thread during a remote execution.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
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
     * The SecurityManager used to retrieve realms that should be associated with the
     * created <tt>Subject</tt>s upon remote invocation.
     */
    private SecurityManager securityManager;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public void setSecurityManager( SecurityManager securityManager ) {
        this.securityManager = securityManager;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    protected InetAddress getInetAddress( RemoteInvocation invocation, Object targetObject ) {
        try {
            return InetAddress.getLocalHost();
        } catch ( UnknownHostException e ) {
            return null;
        }
    }

    protected List getPrincipals( RemoteInvocation invocation, Object targetObject, Session session ) {
        return (List)session.getAttribute( DefaultWebSecurityManager.PRINCIPALS_SESSION_KEY );
    }

    protected boolean isAuthenticated( RemoteInvocation invocation, Object targetObject, Session session, List principals ) {
        return principals != null && !principals.isEmpty();
    }

    @SuppressWarnings( { "unchecked" } )
    public Object invoke( RemoteInvocation invocation, Object targetObject ) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {

        try {
            List principals = null;
            boolean authenticated = false;
            InetAddress inetAddress = getInetAddress( invocation, targetObject );
            Session session = null;

            Serializable sessionId = invocation.getAttribute( SecureRemoteInvocationFactory.SESSION_ID_KEY );

            if ( sessionId != null ) {
                session = securityManager.getSession( sessionId );
                principals = getPrincipals( invocation, targetObject, session );
                authenticated = isAuthenticated( invocation, targetObject, session, principals );
            } else {
                if ( log.isWarnEnabled() ) {
                    log.warn( "RemoteInvocation object did not contain a JSecurity Session id under " +
                        "attribute name [" + SecureRemoteInvocationFactory.SESSION_ID_KEY + "].  A Session will not " +
                        "be available to the method.  Ensure that clients are using a " +
                        "SecureRemoteInvocationFactory to prevent this problem." );
                }
            }

            Subject subject =
                new DelegatingSubject( principals, authenticated, inetAddress, session, securityManager );

            ThreadContext.bind(subject);

            return super.invoke( invocation, targetObject );
            
        } catch ( NoSuchMethodException nsme ) {
            throw nsme;
        } catch ( IllegalAccessException iae ) {
            throw iae;
        } catch ( InvocationTargetException ite ) {
            throw ite;
        } catch ( Throwable t ) {
            throw new InvocationTargetException( t );
        } finally {
            ThreadContext.clear();
        }
    }
}
