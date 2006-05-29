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
package org.jsecurity.ri.util;

import java.io.Serializable;
import java.security.Principal;

/**
 * A principal that represents a username.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class UsernamePrincipal implements Principal, Serializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The username represented by this principal.
     */
    private String username = null;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    /**
     * A default constructor that intializes with a null username.
     */
    public UsernamePrincipal(){}

    /**
     * Constructs a new principal with the given username.
     * @param username the username this principal should represent.
     */
    public UsernamePrincipal( String username ) {
        setUsername( username );
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public String getUsername() {
        return username;
    }

    public void setUsername( String username ) {
        if ( username == null ) {
            String msg = "Cannot accept null username argument";
            throw new NullPointerException( msg );
        }
        this.username = username;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        final UsernamePrincipal that = (UsernamePrincipal) o;

        if (username != null ? !username.equals(that.username) : that.username != null)
            return false;

        return true;
    }


    public int hashCode() {
        return (username != null ? username.hashCode() : 0);
    }


    @Override
    @SuppressWarnings({"CloneDoesntDeclareCloneNotSupportedException"})
    public Object clone() {
        try {
            UsernamePrincipal sp = (UsernamePrincipal)super.clone();
            sp.setUsername( getUsername() ); //Strings are immutable, no need to clone
            return sp;
        } catch ( CloneNotSupportedException e ) {
            throw new InternalError( "Unable to clone StringPrincipal");
        }
    }

    public String toString() {
        return getName();
    }

    public String getName() {
        return getUsername();
    }

}
