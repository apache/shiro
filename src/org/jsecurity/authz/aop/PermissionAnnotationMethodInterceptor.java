/*
 * Copyright (C) 2005-2008 Les Hazlewood
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
package org.jsecurity.authz.aop;

import org.apache.commons.beanutils.BeanUtils;
import org.jsecurity.SecurityManager;
import org.jsecurity.aop.MethodInvocation;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.authz.annotation.PermissionsRequired;
import org.jsecurity.authz.support.InvalidTargetPathException;
import org.jsecurity.util.PermissionUtils;

/**
 * @since 1.0
 * @author Les Hazlewood
 */
public class PermissionAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    private static final char ARRAY_CLOSE_CHAR = ']';

    public PermissionAnnotationMethodInterceptor() {
        setAnnotationClass( PermissionsRequired.class );
    }

    public PermissionAnnotationMethodInterceptor( SecurityManager securityManager ) {
        this();
        setSecurityManager( securityManager );
        init();
    }

    protected String inferTargetFromPath( Object[] methodArgs, String namePath ) throws Exception {
        int propertyStartIndex = -1;

        char[] chars = namePath.toCharArray();
        StringBuffer buf = new StringBuffer();
        //init iteration at index 1 (instead of 0).  This is because the first
        //character must be the ARRAY_OPEN_CHAR (eliminates unnecessary iteration)
        for ( int i = 1; i < chars.length; i++ ) {
            if ( chars[i] == ARRAY_CLOSE_CHAR ) {
                // skip the delimiting period after the ARRAY_CLOSE_CHAR.  The resulting
                // index is the init of the property path that we'll use with
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

    protected Object[] getMethodArguments( MethodInvocation invocation ) {
        if ( invocation != null ) {
            return invocation.getArguments();
        } else {
            return null;
        }
    }

    protected Permission createPermission( MethodInvocation invocation ) {
        PermissionsRequired prAnnotation =  (PermissionsRequired)getAnnotation( invocation );
        Class<? extends Permission> clazz = prAnnotation.type();
        String name = prAnnotation.name();
        String namePath = prAnnotation.namePath();
        if (namePath != null && namePath.length() == 0) {
            namePath = null;
        }
        String actions = prAnnotation.actions();
        if (actions != null && actions.length() == 0) {
            actions = null;
        }

        if ( namePath != null ) {
            try {
                name = inferTargetFromPath( getMethodArguments( invocation ), namePath );
            } catch ( Exception e ) {
                String msg = "Unable to parse namePath property.  Please see the " +
                             "javadoc for expected path syntax. PermissionsRequired check cannot " +
                             "continue.";
                throw new InvalidTargetPathException( msg, e );
            }
        }

        return PermissionUtils.createPermission( clazz, name, actions );
    }

    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {
        Permission p = createPermission( mi );
        if ( getSecurityContext().isPermitted( p ) ) {
            String msg = "Calling SecurityContext does not have required permission [" + p + "].  " +
                    "MethodInvocation denied.";
            throw new UnauthorizedException( msg );
        }
    }


}
