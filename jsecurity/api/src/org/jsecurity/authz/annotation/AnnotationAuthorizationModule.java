/*
 * Copyright (C) 2005 Jeremy Haile
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

import org.jsecurity.authz.AuthorizationAction;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.method.MethodInvocation;
import org.jsecurity.authz.module.AuthorizationModule;
import org.jsecurity.authz.module.AuthorizationVote;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
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
     * @see AuthorizationModule#supports(org.jsecurity.authz.AuthorizationAction)
     *
     * @param action the action that this module is being asked whether or not
     * it supports.
     * @return true if the action is an instance of {@link MethodInvocation} or
     * false otherwise.
     */
    public boolean supports( AuthorizationAction action ) {
        return ( action instanceof MethodInvocation );
    }


    /**
     * Determines whether or not a user is authorized to access a given method
     * based on the annotations of the method.
     *
     * @param context the context of the user being authorized.
     * @param action the action the user is being authorized for.
     * @return granted if the user meets the requirements of the method
     * annotations or denied otherwise.  If there are no supported annotations
     * on the method, this module will abstain.
     */
    public AuthorizationVote isAuthorized( AuthorizationContext context,
                                           AuthorizationAction action ) {

        MethodInvocation mi = (MethodInvocation) action;
        Method method = mi.getMethod();

        boolean authorized = true;
        boolean foundAnnotation = false;

        // If an {@link Authorization} annotation is provided, check all of the
        // annotations it contains
        Authorization authAnnotation = method.getAnnotation( Authorization.class );
        if( authAnnotation != null ) {
            foundAnnotation = true;
            if( !checkAuthorization( context, authAnnotation ) ) {
                authorized = false;
            }
        }

        // Check permission annotation
        HasPermission hpAnnotation = method.getAnnotation( HasPermission.class );
        if( hpAnnotation != null ) {
            foundAnnotation = true;
            if( !checkPermission( context, hpAnnotation ) ) {
                authorized = false;
            }
        }

        // Check role annotation
        HasRole hrAnnotation = method.getAnnotation( HasRole.class );
        if( hrAnnotation != null ) {
            foundAnnotation = true;
            if( !checkRole( context, hrAnnotation ) ) {
                authorized = false;
            }
        }

        // If one of the checks failed, deny authorization
        if( authorized == false ) {
            return AuthorizationVote.denied;

        // If no checks failed and an annotation was found, grant authorization
        } else if( foundAnnotation ) {
            return AuthorizationVote.granted;

        // If no annotations were found, abstain
        } else {
            return AuthorizationVote.abstain;
        }
    }


    private boolean checkAuthorization( AuthorizationContext context,
                                        Authorization authAnnotation ) {

        final AuthorizationAnnotation[] annotations = authAnnotation.value();

        // If no annotations are specified, do not grant authorization
        if( annotations.length == 0 ) {
            return false;
        }

        for( AuthorizationAnnotation annotation : annotations ) {
            if( annotation instanceof HasPermission ) {

                if( !checkPermission( context, (HasPermission)annotation ) ) {
                    return false;
                }

            } else if( annotation instanceof HasRole ) {

                if( !checkRole( context, (HasRole)annotation ) ) {
                    return false;
                }

            } else {
                //todo add logging here
                return false;
            }


        }

        return true;
    }


    private boolean checkRole( AuthorizationContext context,
                               HasRole hrAnnotation ) {
        String roleName = hrAnnotation.value();
        return context.hasRole( roleName );
    }


    private boolean checkPermission( AuthorizationContext context,
                                     HasPermission hpAnnotation ) {
        String type = hpAnnotation.value();
        String name = hpAnnotation.name();
        String[] actions = hpAnnotation.actions();

        // Instantiate the permission instance using reflection
        Permission permission = null;
        try {

            Class clazz = Class.forName( type );

            // Get constructor for permission
            Class[] constructorArgs = new Class[] { String.class, String.class };
            Constructor permConstructor = clazz.getDeclaredConstructor( constructorArgs );

            // Instantiate permission with name and actions specified as attributes
            Object[] constructorObjs = new Object[] { name, actions };
            permission = (Permission) permConstructor.newInstance( constructorObjs );

        } catch ( Exception e ) {
            //todo Add logging here
            return false;
        }

        return context.hasPermission( permission );
    }

}

