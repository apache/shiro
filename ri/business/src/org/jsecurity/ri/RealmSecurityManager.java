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

package org.jsecurity.ri;

import org.jsecurity.realm.Realm;
import org.jsecurity.ri.authc.module.ModularAuthenticator;
import org.jsecurity.ri.realm.RealmManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>Implementation of the {@link SecurityManager} interface that is based around
 * a set of security {@link Realm}s.</p>
 *
 * <p>If an authenticator is not configured, a {@link ModularAuthenticator} is created using
 * the configured realms as the authentication modules for the authenticator.  At least one
 * realm must be configured before {@link #init()} is called for this manager to function properly.</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class RealmSecurityManager extends AbstractSecurityManager implements RealmManager {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * A map from realm name toe realm for all realms managed by this manager.
     */
    private Map<String, Realm> realmMap;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/


    /**
     * Sets the realms managed by this manager.
     * @param realms the realms that should be managed by this manager.
     */
    public void setRealms(List<Realm> realms) {
        this.realmMap = new LinkedHashMap<String, Realm>( realms.size() );

        for( Realm realm : realms ) {

            if( realmMap.containsKey( realm.getName() ) ) {
                throw new IllegalArgumentException( "Two or more realmMap have a non-unique name [" + realm.getName() + "].  All " +
                    "realmMap must have unique names.  Please configure these realmMap with unique names." );
            }

            realmMap.put( realm.getName(), realm );
        }
    }

    @SuppressWarnings( "unchecked" )
    public List<Realm> getAllRealms() {
        if( realmMap != null ) {
            return new ArrayList<Realm>( realmMap.values() );
        } else {
            return Collections.EMPTY_LIST;
        }
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    /**
     * Initializes this realm security manager with a modular authenticator if none is configured and
     * initializes all of the realms that are configured for management.
     */
    @Override
    public void init() {

        if( realmMap == null || realmMap.isEmpty() ) {
            throw new IllegalStateException( "init() called but no realms have been configured " +
                "for this manager.  At least one realm needs to be configured on this manager." );
        }

        super.init();

        if( authenticator == null ) {
            ModularAuthenticator modularAuthenticator = new ModularAuthenticator( getAllRealms() );
            modularAuthenticator.init();
            authenticator = modularAuthenticator;
        }
    }


    /**
     * Retrieves the realm with the given name from the realm map or throws an exception if one
     * is not found.
     * @param realmName the name of the realm to be retrieved.
     * @return the realm to be retrieved.
     * @throws IllegalArgumentException if no realm is found with the given name.
     */
    public Realm getRealm(String realmName) {
        Realm realm = realmMap.get( realmName );
        if( realm == null ) {
            throw new IllegalArgumentException( "No realm found with name [" + realmName + "]" );
        } else {
            return realm;
        }
    }


}