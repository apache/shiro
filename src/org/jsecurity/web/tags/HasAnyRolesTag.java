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
package org.jsecurity.web.tags;

import org.jsecurity.subject.Subject;

/**
 * Displays body content if the current user has any of the roles specified.
 * @since 0.2
 * @author Jeremy Haile
 */
public class HasAnyRolesTag extends RoleTag {

    // Delimeter that separates role names in tag attribute
    private static final String ROLE_NAMES_DELIMETER = ",";

    public HasAnyRolesTag(){}

    protected boolean showTagBody( String roleNames ) {
        boolean hasAnyRole = false;

        Subject subject = getSubject();

        if( subject != null ) {

            // Iterate through roles and check to see if the user has one of the roles
            for( String role : roleNames.split(ROLE_NAMES_DELIMETER) ) {

                if( subject.hasRole( role.trim() ) ) {
                    hasAnyRole = true;
                    break;
                }

            }

        }

        return hasAnyRole;
    }

}
