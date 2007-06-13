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
