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

package org.jsecurity.util;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.ThreadLocalSecurityContext;

import java.security.Permission;

/**
 * Utility object that can be used for templating frameworks such as
 * Velocity to make accessing the current {@link org.jsecurity.context.SecurityContext} easier.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class JSecurityTool {

    /**
     * The current <tt>SecurityContext</tt>.
     */
    private SecurityContext securityContext;


    /**
     * Initializes a new <tt>JSecurityTool</tt> for the given security context.
     *
     * The security context may typically be retrieved using
     * {@link ThreadLocalSecurityContext#current()}
     *
     * @param securityContext the current security context.
     */
    public JSecurityTool(SecurityContext securityContext) {
        if( securityContext == null ) {
            throw new IllegalArgumentException( "Security context cannot be null." );
        }
        this.securityContext = securityContext;
    }


    protected SecurityContext getSecurityContext() {
        return this.securityContext;
    }

    public boolean isAuthenticated() {
        return getSecurityContext().isAuthenticated();
    }

    public boolean hasRole( String roleName ) {
        return getSecurityContext().hasRole( roleName );
    }

    public boolean lacksRole( String roleName ) {
        boolean hasRole = getSecurityContext().hasRole( roleName );
        return !hasRole;
    }

    public boolean implies( Permission p ) {
        return getSecurityContext().implies( p );
    }

    public boolean notImplies( Permission p ) {
        boolean permitted = getSecurityContext().implies( p );
        return !permitted;
    }

}