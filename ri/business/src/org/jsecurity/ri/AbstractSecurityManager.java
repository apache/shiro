/*
 * Copyright (C) 2006 Jeremy Haile, Les Hazlewood
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

package org.jsecurity.ri;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.ri.authz.module.AnnotationsModularAuthorizer;

/**
 * <p>Abstract implementation of the <code>SecurityManager</code> interface that delegates its authentication and
 * authorization operations to an internal encapsulated {@link Authenticator} and {@link Authorizer} instance,
 * respectively.  It also provides some sensible defaults to simplify configuration.
 *
 * <p>This implementation is primarily a convenience mechanism that wraps both instances to consolidate
 * both behaviors into a single point of reference.  For most JSecurity users, this simplifies configuration and
 * tends to be a more convenient approach than referencing the <code>Authenticator</code> and <code>Authorizer</code>
 * instances seperately.
 *
 * <p><b>N.B.</b> Unless specified otherwise, the {@link #setAuthorizer Authorizer} property defaults to an
 * {@link AnnotationsModularAuthorizer} instance to simplify configuration.  There is <strong>no default</strong>
 * {@link #setAuthenticator Authenticator} created by this <code>SecurityManager</code> abstract implementation, as it is expected to be
 * specified by Dependency Injection or by subclass implementations.</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public abstract class AbstractSecurityManager implements SecurityManager {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The authenticator that is delegated to for authentication purposes.
     */
    protected Authenticator authenticator;

    /**
     * The authorizer that is delegated to for authorization purposes.
     */
    protected Authorizer authorizer = new AnnotationsModularAuthorizer();

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public void init() {
        if ( this.authorizer == null ) {
            throw new IllegalStateException( "authorizer property must be set." );
        }
        onInit();
    }

    protected void onInit(){}

    /**
     * Delegates to the authenticator for authentication.
     */
    public AuthorizationContext authenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        return authenticator.authenticate( authenticationToken );
    }

    /**
     * Delegates to the authorizer for autorization.
     */
    public boolean isAuthorized(AuthorizationContext context, AuthorizedAction action) {
        return authorizer.isAuthorized( context, action );
    }

    /**
     * Delegates to the authorizer for authorization.
     */
    public void checkAuthorization(AuthorizationContext context, AuthorizedAction action) throws AuthorizationException {
        authorizer.checkAuthorization( context, action );
    }

}