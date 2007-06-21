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

import org.aopalliance.intercept.MethodInvocation;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;
import org.springframework.remoting.support.DefaultRemoteInvocationFactory;
import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.remoting.support.RemoteInvocationFactory;

import java.io.Serializable;

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
        Session session = ThreadContext.getSession();

        Serializable sessionId;
        if( session != null ) {
            sessionId = session.getSessionId();
        } else {
            sessionId = System.getProperty( "jsecurity.session.id" );
        }

        if( sessionId != null ) {
            return new SecureRemoteInvocation( methodInvocation, sessionId );
        } else {
            return super.createRemoteInvocation( methodInvocation );
        }

    }
}
