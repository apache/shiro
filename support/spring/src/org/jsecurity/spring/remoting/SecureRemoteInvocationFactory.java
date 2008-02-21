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
import org.springframework.remoting.support.DefaultRemoteInvocationFactory;
import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.remoting.support.RemoteInvocationFactory;

/**
 * A {@link RemoteInvocationFactory} that passes the session ID to the server via a
 * {@link RemoteInvocation} {@link RemoteInvocation#getAttribute(String) attribute}.
 * This factory is the client-side part of
 * the JSecurity Spring remoting invocation.  A {@link SecureRemoteInvocationExecutor} should
 * be used to export the server-side remote services to ensure that the appropriate
 * Subject and Session are bound to the remote thread during execution.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class SecureRemoteInvocationFactory extends DefaultRemoteInvocationFactory {

    public static final String SESSION_ID_KEY = Session.class.getName() + "_ID_KEY";

    private static final String SESSION_ID_SYSTEM_PROPERTY_NAME = "jsecurity.session.id";

    /**
     * Creates a {@link RemoteInvocation} with the current session ID as an
     * {@link RemoteInvocation#getAttribute(String) attribute}.
     * @param methodInvocation the method invocation that the remote invocation should
     * be based on.
     * @return a remote invocation object containing the current session ID as an attribute.
     */
    public RemoteInvocation createRemoteInvocation(MethodInvocation methodInvocation) {
        String sessionId = System.getProperty(SESSION_ID_SYSTEM_PROPERTY_NAME);
        if( sessionId == null ) {
            throw new IllegalStateException( "System property [" + SESSION_ID_SYSTEM_PROPERTY_NAME + "] is not set.  " +
                    "This property must be set to the JSecurity session ID for remote calls to function." );
        }
        RemoteInvocation ri = new RemoteInvocation(methodInvocation);
        ri.addAttribute( SESSION_ID_KEY, sessionId );

        return ri;
    }
}
