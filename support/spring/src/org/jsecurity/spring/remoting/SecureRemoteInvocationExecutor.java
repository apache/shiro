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
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.support.SecurityContextWebInterceptor;
import org.springframework.remoting.support.DefaultRemoteInvocationExecutor;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.security.Principal;
import java.util.List;

/**
 * An implementation of the Spring {@link org.springframework.remoting.support.RemoteInvocationExecutor}
 * that binds the correct {@link Session} and {@link org.jsecurity.context.SecurityContext} to the
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
     * The realm manager used to retrieve realms that should be associated with the
     * created authorization contexts upon remote invocation.
     */
    private SecurityManager securityManager;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    @SuppressWarnings({"unchecked"})
    public Object invoke(RemoteInvocation invocation, Object targetObject) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {

        try {

            if( invocation instanceof SecureRemoteInvocation ) {
                SecureRemoteInvocation secureInvocation = (SecureRemoteInvocation) invocation;

                Serializable sessionId = secureInvocation.getSessionId();
                Session session = securityManager.getSession( sessionId );
                ThreadContext.bind( session );

                // Get the principals and realm name from the session
                List<Principal>principals = (List<Principal>) session.getAttribute( SecurityContextWebInterceptor.PRINCIPALS_SESSION_KEY );

                // If principals and realm were found in the session, create a delegating authorization context
                // and bind it to the thread.
                if( principals != null && !principals.isEmpty() ) {
                    SecurityContext securityContext = new DelegatingSecurityContext( principals, securityManager );
                    ThreadContext.bind( securityContext );
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
            ThreadContext.unbindSession();
        }
    }
}
