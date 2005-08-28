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
package org.jsecurity.authz.module;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.annotation.HasRole;
import org.jsecurity.authz.method.MethodInvocation;

import java.lang.reflect.Method;

/**
 * AuthorizationModule that votes on authorization based on any
 * {@link org.jsecurity.authz.annotation.HasRole HasRole} annotation found on the method
 * being executed.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class RoleAnnotationAuthorizationModule extends AnnotationAuthorizationModule {

    public RoleAnnotationAuthorizationModule() {
        setAnnotationClass( HasRole.class );
    }

    public AuthorizationVote isAuthorized( AuthorizationContext context, AuthorizedAction action ) {

        MethodInvocation mi = (MethodInvocation)action;

        if ( mi != null ) {

            Method m = mi.getMethod();
            if ( m == null ) {
                String msg = MethodInvocation.class.getName() + " parameter incorrectly " +
                             "constructed.  getMethod() returned null";
                throw new NullPointerException( msg );
            }

            HasRole hrAnnotation = m.getAnnotation( HasRole.class );
            if ( hrAnnotation != null ) {
                if ( log.isTraceEnabled() ) {
                    log.trace( "Found role annotation for role [" + hrAnnotation.value() + "]" );
                }
                if ( context.hasRole( hrAnnotation.value() ) ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "Authorization context has role [" +
                                   hrAnnotation.value() + "]. Returning grant vote.");
                    }
                    return AuthorizationVote.grant;
                } else {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "AuthorizationContext does not have role [" +
                                   hrAnnotation.value() + "].  Returning deny vote.");
                    }
                    return AuthorizationVote.deny;
                }

            } else {
                if ( log.isInfoEnabled() ) {
                    log.info( "No " + HasRole.class.getName() + " annotation declared for " +
                              "method " + m + ".  Returning abstain vote." );
                }
                return AuthorizationVote.abstain;
            }
        } else {
            if ( log.isWarnEnabled() ) {
                log.warn( "AuthorizedAction parameter is null.  Returning abstain vote." );
            }
            return AuthorizationVote.abstain;
        }

    }

}
