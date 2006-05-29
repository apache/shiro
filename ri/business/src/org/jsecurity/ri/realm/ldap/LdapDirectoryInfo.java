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
package org.jsecurity.ri.realm.ldap;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

/**
 * An object containing LDAP directory information queried from an
 * LDAP server.  This class can be subclassed to contain
 * additional information for more advanced implementations.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class LdapDirectoryInfo {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Additional principals returned from the LDAP query that should be included in the
     * authorization context.
     */
    protected List<Principal> principals;

    /**
     * The role names that were determined from the LDAP server.
     */
    protected Collection<String> roleNames;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    public LdapDirectoryInfo() {
        this.principals = new ArrayList<Principal>();
        this.roleNames = new HashSet<String>();
    }

    public LdapDirectoryInfo(List<Principal> principals, Collection<String> roleNames) {
        this.principals = principals;
        this.roleNames = roleNames;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public Collection<Principal> getPrincipals() {
        return principals;
    }

    public void setPrincipals(List<Principal> principals) {
        this.principals = principals;
    }

    public void addPrincipal(Principal principal) {
        this.principals.add( principal );
    }

    public void addAllPrincipals( Collection<Principal> principals ) {
        this.principals.addAll( principals );
    }

    public Collection<String> getRoleNames() {
        return roleNames;
    }

    public void setRoleNames(Collection<String> roleNames) {
        this.roleNames = roleNames;
    }

    public void addRoleName(String roleName) {
        this.roleNames.add( roleName );
    }

    public void addAllRoleNames( Collection<String> roleNames ) {
        this.roleNames.addAll( roleNames );
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
}
