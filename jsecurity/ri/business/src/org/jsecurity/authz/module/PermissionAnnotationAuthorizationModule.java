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

import org.apache.commons.beanutils.BeanUtils;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.annotation.HasPermission;
import org.jsecurity.authz.method.MethodInvocation;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Permission;

/**
 * AuthorizationModule that votes on authorization based on any {@link
 * org.jsecurity.authz.annotation.HasPermission HasPermission} annotation found on the method being
 * executed.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public class PermissionAnnotationAuthorizationModule extends AnnotationAuthorizationModule {

    private static final char ARRAY_CLOSE_CHAR = ']';

    private String inferTargetFromPath( Object[] methodArgs, String targetPath ) throws Exception {
        int propertyStartIndex = -1;

        char[] chars = targetPath.toCharArray();
        StringBuffer buf = new StringBuffer();
        //start iteration at index 1 (instead of 0).  This is because the first
        //character must be the ARRAY_OPEN_CHAR (eliminates unnecessary iteration)
        for ( int i = 1; i < chars.length; i++ ) {
            if ( chars[i] == ARRAY_CLOSE_CHAR ) {
                // skip the delimiting period after the ARRAY_CLOSE_CHAR.  The resulting
                // index is the start of the property path that we'll use with
                // BeanUtils.getProperty:
                propertyStartIndex = i + 2;
                break;
            } else {
                buf.append( chars[i] );
            }
        }

        Integer methodArgIndex = Integer.parseInt( buf.toString() );
        String beanUtilsPath = new String( chars, propertyStartIndex, chars.length - propertyStartIndex );
        Object targetValue = BeanUtils.getProperty( methodArgs[methodArgIndex], beanUtilsPath );
        return targetValue.toString();
    }

    private Permission instantiatePermission( Class<? extends Permission> clazz,
                                              String name, String[] actions ) {
        // Instantiate the permission instance using reflection
        Permission permission;
        try {
            // Get constructor for permission
            Class[] constructorArgs = new Class[]{String.class, String.class};
            Constructor permConstructor = clazz.getDeclaredConstructor( constructorArgs );

            // Instantiate permission with name and actions specified as attributes
            Object[] constructorObjs = new Object[]{name, actions};
            permission = (Permission)permConstructor.newInstance( constructorObjs );
            return permission;
        } catch ( Exception e ) {
            String msg = "Unable to instantiate Permission class [" + clazz.getName() + "].  " +
                         "HasPermission check cannot continue.";
            throw new IllegalStateException( msg, e );
        }
    }

    private Permission createPermission( MethodInvocation mi, HasPermission hp ) {
        Class<? extends Permission> clazz = hp.type();
        String target = hp.target();
        String targetPath = hp.targetPath();
        if ( targetPath.equals( "" ) ) {
            targetPath = null;
        }
        String[] actions = hp.actions();

        if ( targetPath != null ) {
            try {
                target = inferTargetFromPath( mi.getArguments(), targetPath );
            } catch ( Exception e ) {
                String msg = "Unable to parse targetPath property.  Please see the " +
                             "javadoc for expected path syntax. HasPermission check cannot " +
                             "continue.";
                //todo - create a meaningful exception:
                throw new RuntimeException( msg );
            }
        }
        return instantiatePermission( clazz, target, actions );
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

            HasPermission hpAnnotation = m.getAnnotation( HasPermission.class );
            if ( hpAnnotation != null ) {
                if ( log.isTraceEnabled() ) {
                    log.trace( "Found permission annotation [" + hpToString( hpAnnotation ) + "]" );
                }
                Permission p = createPermission( mi, hpAnnotation );
                if ( context.hasPermission( p ) ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "Authorization context has permission [" + p +
                                   "]. Returning grant vote." );
                    }
                    return AuthorizationVote.grant;
                } else {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "AuthorizationContext does not have permission [" + p +
                                   "].  Returning deny vote." );
                    }
                    return AuthorizationVote.deny;
                }

            } else {
                if ( log.isInfoEnabled() ) {
                    log.info( "No " + HasPermission.class.getName() + " annotation declared for " +
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

    private String hpToString( HasPermission annotation ) {
        StringBuffer sb = new StringBuffer();
        sb.append( "type=" ).append( annotation.type() );
        sb.append( ",target=" ).append( annotation.target() );
        sb.append( ",targetPath=" ).append( annotation.targetPath() );
        sb.append( ",actions=[" ).append( annotation.actions() ).append( "]" );
        return sb.toString();
    }

}
