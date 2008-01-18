/*
* Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.context.factory.support;

import org.jsecurity.SecurityManager;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.InetAuthenticationToken;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;

import java.net.InetAddress;

/**
 * SecurityContextFactory implementation that creates
 * {@link org.jsecurity.context.support.DelegatingSecurityContext} instances.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class DelegatingSecurityContextFactory extends AbstractSecurityContextFactory {

    private SecurityManager securityManager;

    public DelegatingSecurityContextFactory( SecurityManager securityManager ){
        this.securityManager = securityManager;
    }

    protected SecurityContext onCreateSecurityContext( AuthenticationToken token, Account account ) {

        //get any existing session that may exist - we don't want to lose it:
        SecurityContext securityContext = ThreadContext.getSecurityContext();
        Session session = null;
        if ( securityContext != null ) {
            session = securityContext.getSession( false );
        }

        InetAddress authcSourceIP = null;
        if( token instanceof InetAuthenticationToken ) {
            authcSourceIP = ((InetAuthenticationToken)token).getInetAddress();
        }
        if ( authcSourceIP == null ) {
            //try the thread local:
            authcSourceIP = ThreadContext.getInetAddress();
        }

        return new DelegatingSecurityContext( account.getPrincipals(), true, authcSourceIP, session, securityManager );
    }
}
