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
import org.jsecurity.authz.annotation.HasPermission;
import org.jsecurity.authz.method.MethodInvocation;

import java.lang.annotation.IncompleteAnnotationException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Permission;

/**
 * AuthorizationModule that votes on authorization based on any
 * {@link org.jsecurity.authz.annotation.HasPermission HasPermission} annotation found on the
 * method being executed.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class PermissionAnnotationAuthorizationModule extends AnnotationAuthorizationModule {

    //todo - implementation in progress:
    private Permission createPermission( MethodInvocation mi, HasPermission hp ) {
        Class<? extends Permission> clazz = hp.type();
        String name = hp.target();
        String[] actions = hp.actions();

        Method m = mi.getMethod();

        String target;

        if ( name == null ) {
            /*int targetIndex = hp.targetIndex();
            if ( targetIndex >= 0 ) {
                Object[] args = mi.getArguments();
                if ( args == null || (args.length < 1 ) ) {
                    String msg = HasPermission.class.getName() + " targetIndex specified but " +
                                 "the method does not have any arguments!";
                    throw new IndexOutOfBoundsException( msg );
                }
                if ( targetIndex >= args.length ) {
                    String msg = HasPermission.class.getName() + " targetIndex [" +
                                 targetIndex + "] specified, but the method argument array is " +
                                 "only of length [" + args.length + "]";
                    throw new ArrayIndexOutOfBoundsException( msg );
                }

                Object targetObject = args[targetIndex];

                String targetMethodName = hp.targetPath();

                if ( targetMethodName != null ) {
                    Object targetMethodRetVal = invokeMethod( targetObject, targetMethodName);
                    target = targetMethodRetVal.toString();
                } else {
                    target = targetObject.toString();
                }
            } else {
                String msg = "target or targetIndex on delcaring method " +
                             m.getDeclaringClass().getName() + "." + m.getName() + ".  At least " +
                             "one of the two is required.";
                throw new IncompleteAnnotationException( HasPermission.class, msg );
            }*/
        } else {
            target = name;
        }

        //return instantiatePermission( clazz, target, actions );

        //dummy statement to allow compilation - still working on method:
        return new java.io.FilePermission( "dummyFile.txt", "read" );
    }

    private Object invokeMethod( Object o, String methodName ) {
        try {
            Method m = o.getClass().getDeclaredMethod( methodName, (Class[])null );
            return m.invoke( o, (Object[])null );
        } catch ( Exception e ) {
            String msg = "Unable to invoke " + HasPermission.class.getName() +
                         " targetMethodName '" + methodName + "'";
            throw new IllegalArgumentException( msg, e );
        }
    }

    private Permission instantiatePermission(Class<Permission> clazz, String name, String[] actions ) {
        // Instantiate the permission instance using reflection
        Permission permission;
        try {
            // Get constructor for permission
            Class[] constructorArgs = new Class[] { String.class, String.class };
            Constructor permConstructor = clazz.getDeclaredConstructor( constructorArgs );

            // Instantiate permission with name and actions specified as attributes
            Object[] constructorObjs = new Object[] { name, actions };
            permission = (Permission) permConstructor.newInstance( constructorObjs );
            return permission;
        } catch ( Exception e ) {
            String msg = "Unable to instantiate Permission class [" + clazz.getName() + "].  " +
                         "Annotation check cannot continue.";
            throw new IllegalStateException( msg, e );
        }
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
                                   "]. Returning grant vote.");
                    }
                    return AuthorizationVote.grant;
                } else {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "AuthorizationContext does not have permission [" + p +
                                   "].  Returning deny vote.");
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
        sb.append("type=").append(annotation.type() );
        sb.append(",target=").append(annotation.target());
        sb.append(",targetPath=").append(annotation.targetPath());
        sb.append(",actions=[").append(annotation.actions()).append("]");
        return sb.toString();
    }

}
