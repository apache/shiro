/*
* Copyright (C) 2005 Les Hazlewood
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
package org.jsecurity.ri.authz.support;

import org.jsecurity.authc.module.AuthenticationInfo;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.ri.authz.DelegatingAuthorizationContext;
import org.jsecurity.ri.authz.Realm;

/**
 * AuthorizationContextFactory implementation that creates
 * {@link DelegatingAuthorizationContext} instances.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class DelegatingAuthorizationContextFactory extends AbstractAuthorizationContextFactory {

    private Realm realm = null;

    public DelegatingAuthorizationContextFactory(){}

    public void setRealm( Realm realm ) {
        this.realm = realm;
    }

    public void init() {
        if ( this.realm == null ) {
            String msg = "realm property must be set";
            throw new IllegalStateException( msg );
        }
    }

    protected AuthorizationContext onCreateAuthorizationContext( AuthenticationInfo info ) {
        return new DelegatingAuthorizationContext( info.getPrincipals(), this.realm );
    }
}
