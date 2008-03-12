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
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.authz.annotation.RequiresPermissions;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.PermissionUtils;

import java.util.Set;

/**
 * @since 0.9
 * @author Les Hazlewood
 */
public class PermissionAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    private static final char ARRAY_CLOSE_CHAR = ']';

    public PermissionAnnotationMethodInterceptor() {
        setAnnotationClass( RequiresPermissions.class );
    }

    public PermissionAnnotationMethodInterceptor( SecurityManager securityManager ) {
        this();
        setSecurityManager( securityManager );
        init();
    }

    protected String inferTargetFromPath( Object[] methodArgs, String namePath ) throws Exception {
        int propertyStartIndex = -1;

        char[] chars = namePath.toCharArray();
        StringBuilder buf = new StringBuilder();
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

    protected String getAnnotationValue( MethodInvocation invocation ) {
        RequiresPermissions prAnnotation =  (RequiresPermissions)getAnnotation( invocation );
        return prAnnotation.value();
    }

    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {
        String p = getAnnotationValue( mi );
        Set<String> perms = PermissionUtils.toPermissionStrings(p);

        Subject subject = getSubject();

        if ( perms.size() == 1 ) {
            if ( !subject.isPermitted(perms.iterator().next()) ) {
                String msg = "Calling Subject does not have required permission [" + p + "].  " +
                    "Method invocation denied.";
                throw new UnauthorizedException( msg );    
            }
        } else {
            String[] permStrings = new String[perms.size()];
            permStrings = perms.toArray(permStrings);
            if ( !subject.isPermittedAll(permStrings)) {
                 String msg = "Calling Subject does not have required permissions [" + p + "].  " +
                              "Method invocation denied.";
                 throw new UnauthorizedException(msg);
            }

        }
    }


}
