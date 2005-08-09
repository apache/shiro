/*
 * Copyright (C) 2005 Jeremy Haile, Les A. Hazlewood
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

package org.jsecurity.authz.annotation;

import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.method.MethodInvocation;
import org.jsecurity.authz.module.AuthorizationModule;
import org.jsecurity.authz.module.AuthorizationVote;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.annotation.IncompleteAnnotationException;
import java.security.Permission;


/**
 * An {@link org.jsecurity.authz.module.AuthorizationModule} that votes on
 * whether or not a user is authorized to access a method based on the
 * annotations of the method being executed.
 * <p>This method only supports voting on authorization actions of type
 * {@link org.jsecurity.authz.method.MethodInvocation}</p>
 *
 * todo I don't really like this implementation.  Should this be generalized to support further annotations?  I'm only worried it might make configuration more difficult -JCH
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class AnnotationAuthorizationModule implements AuthorizationModule {

    /*------------------------------------
     *         C O N S T A N T S         |
     *================================== */

    /*------------------------------------
     *          I N S T A N C E          |
     *================================== */

    /*------------------------------------
     *       C O N S T R U C T O R S     |
     *================================== */

    /*------------------------------------
     *   A C C E S S / M O D I F I E R   |
     *================================== */

    /*------------------------------------
     *           M E T H O D S           |
     *================================== */
    /**
     * @see AuthorizationModule#supports(org.jsecurity.authz.AuthorizedAction)
     *
     * @param action the action that this module is being asked whether or not
     * it supports.
     * @return true if the action is an instance of {@link MethodInvocation} or
     * false otherwise.
     */
    public boolean supports( AuthorizedAction action ) {
        return ( action instanceof MethodInvocation );
    }


    /**
     * Determines whether or not a user is authorized to access a given method
     * based on the annotations of the method.
     *
     * @param context the context of the user being authorized.
     * @param action the action the user is being authorized for.
     * @return grant if the user meets the requirements of the method
     * annotations or deny otherwise.  If there are no supported annotations
     * on the method, this module will abstain.
     */
    public AuthorizationVote isAuthorized( AuthorizationContext context,
                                           AuthorizedAction action ) {

        MethodInvocation mi = (MethodInvocation) action;
        Method method = mi.getMethod();

        boolean authorized = true;
        boolean foundAnnotation = false;

        // Check permission annotation
        HasPermission hpAnnotation = method.getAnnotation( HasPermission.class );
        if( hpAnnotation != null ) {
            foundAnnotation = true;
            Permission p = createPermission( mi, hpAnnotation );
            if( !context.hasPermission( p ) ) {
                authorized = false;
            }
        }

        // Check role annotation
        HasRole hrAnnotation = method.getAnnotation( HasRole.class );
        if( hrAnnotation != null ) {
            foundAnnotation = true;
            if ( !context.hasRole( hrAnnotation.value() ) ) {
                authorized = false;
            }
        }

        // If one of the checks failed, deny authorization
        if( !authorized ) {
            return AuthorizationVote.deny;
        // If no checks failed and an annotation was found, grant authorization
        } else if( foundAnnotation ) {
            return AuthorizationVote.grant;
        // If no annotations were found, abstain
        } else {
            return AuthorizationVote.abstain;
        }
    }

    private Permission createPermission( MethodInvocation mi, HasPermission hp ) {
        Class<Permission> clazz = hp.type();
        String name = hp.target();
        String[] actions = hp.actions();

        Method m = mi.getMethod();

        String target;

        if ( name == null ) {
            int targetIndex = hp.targetIndex();
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

                String targetMethodName = hp.targetMethodName();

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
            }
        } else {
            target = name;
        }

        return instantiatePermission( clazz, target, actions );
    }

    private Object invokeMethod( Object o, String methodName ) {
        try {
            Method m = o.getClass().getDeclaredMethod( methodName, null );
            return m.invoke( o, null );
        } catch ( Exception e ) {
            String msg = "Unable to invoke " + HasPermission.class.getName() +
                " targetMethodName '" + methodName + "'";
            throw new IllegalArgumentException( msg, e );
        }
    }

    private Permission instantiatePermission(Class<Permission> clazz, String name, String[] actions ) {
        // Instantiate the permission instance using reflection
        Permission permission = null;
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
}

