/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.authz.module.support;

import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.annotation.RolesRequired;
import org.jsecurity.authz.module.AuthorizationVote;
import org.jsecurity.context.SecurityContext;

/**
 * AuthorizationModule that votes on authorization based on any {@link
 * org.jsecurity.authz.annotation.RolesRequired RolesRequired} annotation found on the method
 * being executed.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class RoleAnnotationAuthorizationModule extends AnnotationAuthorizationModule {

    @SuppressWarnings({"OverridableMethodCallInConstructor"})
    public RoleAnnotationAuthorizationModule() {
        setAnnotationClass( RolesRequired.class );
    }

    public AuthorizationVote isAuthorized( SecurityContext context, AuthorizedAction action ) {

        RolesRequired rrAnnotation = (RolesRequired)getAnnotation( action );

        String roleId = rrAnnotation.value();

        if ( context.hasRole( roleId ) ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "SecurityContext has role [" + roleId +
                           "]. Returning grant vote." );
            }
            return AuthorizationVote.grant;
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "SecurityContext does not have role [" +  roleId +
                           "].  Returning deny vote." );
            }
            return AuthorizationVote.deny;
        }
    }

}
