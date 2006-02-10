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
package org.jsecurity.ri.authz.module;

import org.apache.commons.beanutils.BeanUtils;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.annotation.Implies;
import org.jsecurity.authz.method.MethodInvocation;
import org.jsecurity.authz.module.AuthorizationVote;
import org.jsecurity.ri.util.PermissionUtils;

import java.lang.reflect.Method;
import java.security.Permission;

/**
 * AuthorizationModule that votes on authorization based on any {@link
 * org.jsecurity.authz.annotation.Implies Implies} annotation found on the method being
 * executed.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class PermissionAnnotationAuthorizationModule extends AnnotationAuthorizationModule {

    private static final char ARRAY_CLOSE_CHAR = ']';

    @SuppressWarnings({"OverridableMethodCallInConstructor"})
    public PermissionAnnotationAuthorizationModule() {
        setAnnotationClass( Implies.class );
    }

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
        String beanUtilsPath = new String( chars, propertyStartIndex,
                                           chars.length - propertyStartIndex );
        Object targetValue = BeanUtils.getProperty( methodArgs[methodArgIndex], beanUtilsPath );
        return targetValue.toString();
    }

    private Permission createPermission( MethodInvocation mi, Implies implies ) {
        Class<? extends Permission> clazz = implies.type();
        String target = implies.target();
        String targetPath = implies.targetPath();
        if ( targetPath.equals( "" ) ) {
            targetPath = null;
        }
        String actions = implies.actions();
        if ( actions.equals( "" ) ) {
            actions = null;
        }

        if ( targetPath != null ) {
            try {
                target = inferTargetFromPath( mi.getArguments(), targetPath );
            } catch ( Exception e ) {
                String msg = "Unable to parse targetPath property.  Please see the " +
                             "javadoc for expected path syntax. Implies check cannot " +
                             "continue.";
                throw new InvalidTargetPathException( msg, e );
            }
        }

        if ( actions == null ) {
            return PermissionUtils.createPermission( clazz, target );
        } else {
            return PermissionUtils.createPermission( clazz, target, actions );
        }
    }

    public AuthorizationVote isAuthorized( AuthorizationContext context, AuthorizedAction action ) {

        MethodInvocation mi = (MethodInvocation)action;

        Method m = mi.getMethod();
        if ( m == null ) {
            String msg = MethodInvocation.class.getName() + " parameter incorrectly " +
                         "constructed.  getMethod() returned null";
            throw new NullPointerException( msg );
        }

        Implies implies = m.getAnnotation( Implies.class );

        Permission p = createPermission( mi, implies );
        if ( context.implies( p ) ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Authorization context implies permission [" + p +
                           "]. Returning grant vote." );
            }
            return AuthorizationVote.grant;
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "AuthorizationContext does not imply permission [" + p +
                           "].  Returning deny vote." );
            }
            return AuthorizationVote.deny;
        }
    }


    /*private String hpToString( Implies annotation ) {
        StringBuffer sb = new StringBuffer();
        sb.append( "type=" ).append( annotation.type() );
        sb.append( ",target=" ).append( annotation.target() );
        sb.append( ",targetPath=" ).append( annotation.targetPath() );
        sb.append( ",actions=[" ).append( annotation.actions() ).append( "]" );
        return sb.toString();
    }*/

}
