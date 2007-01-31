/*
 * Copyright (C) 2006 Jeremy Haile
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

import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.AuthorizationOperations;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.realm.Realm;

import java.util.List;

/**
 * A <tt>SecurityManager</tt> is a convenience mechanism - it extends both the {@link Authenticator} and
 * {@link Authorizer} interfaces, thereby consolidating both behaviors into one.  This allows applications to
 * interact with a single component for most JSecurity operations should they choose to do so.
 *
 * @see DefaultSecurityManager
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public interface SecurityManager extends Authenticator, Authorizer, AuthorizationOperations {

    /**
     * Retrieves a realm by its unique name.
     * @param realmName the unique name of the realm to be retrieved.
     * @return the realm associated with the given name.
     * @throws IllegalArgumentException if a realm with the given name is not found.
     */
    Realm getRealm( String realmName ) throws IllegalArgumentException;


    /**
     * Sets the realms that should be managed by this realm manager.
     * @param realms the realms that should be managed by this realm manager.
     */
    void setRealms( List<Realm> realms );


    /**
     * Returns all realms that are managed by this realm manager.
     * @return a list of realms that are managed by this realm manager.
     */
    List<Realm> getAllRealms();

}