/*
 * Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity.context;

import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;


/**
 * Default implementation of the {@link SecurityContext} interface used
 * by the reference implementation.
 *
 * @author Jeremy Haile
 * @since 0.1
 */
public class DefaultSecurityContext extends SecurityContext {

    /*--------------------------------------------
     |             C O N S T A N T S             |
     ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private SessionFactory sessionFactory;

    private Authenticator authenticator;

    private Authorizer authorizer;

    private Session currentSession;

    private AuthorizationContext currentAuthContext;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }


    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }


    public Authenticator getAuthenticator() {
        return authenticator;
    }


    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }


    public Authorizer getAuthorizer() {
        return authorizer;
    }


    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }


    public Session getCurrentSession() {
        return currentSession;
    }


    public void setCurrentSession(Session currentSession) {
        this.currentSession = currentSession;
    }


    public AuthorizationContext getCurrentAuthContext() {
        return currentAuthContext;
    }


    public void setCurrentAuthContext(AuthorizationContext currentAuthContext) {
        this.currentAuthContext = currentAuthContext;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public void invalidate() {
        
    }


    /*--------------------------------------------
    |     A B S T R A C T   M E T H O D S       |
    ============================================*/

}