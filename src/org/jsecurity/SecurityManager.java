/*
 * Copyright (C) 2005-2007 Jeremy Haile
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
package org.jsecurity;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.SessionFactory;

import java.util.Collection;

/**
 * A <tt>SecurityManager</tt> is a convenience mechanism - it extends the {@link Authenticator},
 * {@link Authorizer}, and {@link SessionFactory} interfaces, thereby consolidating
 * these behaviors into a single interface.  This allows applications to interact with a single
 * <tt>SecurityManager</tt> component for most JSecurity operations should they choose to do so.
 *
 * @see DefaultSecurityManager
 *
 * @since 0.2
 * 
 * @author Jeremy Haile
 */
public interface SecurityManager extends Authenticator, Authorizer, SessionFactory {

    /**
     * Returns the realm with the specified unique name or <tt>null</tt> if there is no realm managed by the
     * SecurityManager instance by that name.
     *
     * @param realmName the unique name of the realm to be retrieved.
     * @return the realm with the specified unique name or <tt>null</tt> if there is no realm managed by the
     * SecurityManager instance by that name.
     */
    Realm getRealm( String realmName );

    /**
     * Returns all realms that are managed by this SecurityManager.
     * @return a list of realms that are managed by this SecurityManager.
     */
    Collection<Realm> getAllRealms();

    SecurityContext login( AuthenticationToken authenticationToken ) throws AuthenticationException;

    /**
     * Returns the calling context's <tt>SecurityContext</tt>.
     * @return the calling context's <tt>SecurityContext</tt>.
     */
    SecurityContext getSecurityContext();
}