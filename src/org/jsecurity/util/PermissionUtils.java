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
package org.jsecurity.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.Constructor;
import java.security.Permission;

/**
 * @since 0.1
 * @author Les Hazlewood
 */
public class PermissionUtils {

    protected static transient final Log log = LogFactory.getLog( PermissionUtils.class );

    private static void assertTarget( String nameOrTarget ) {
        if ( nameOrTarget == null ) {
            String msg = "name (a.k.a. target) String argument cannot be null";
            throw new IllegalArgumentException( msg );
        }
    }

    private static Permission instantiate( Constructor<? extends Permission> c, Object[] args ) {
        Permission p;
        try {
            p = c.newInstance( args );
        } catch ( Exception e ) {
            String msg = "Unable to instantiate Permission instance with constructor [" + c + "]";
            throw new PermissionInstantiationException( msg, e );
        }
        return p;
    }

    public static Permission createPermission( Class<? extends Permission> clazz, String nameOrTarget ) {

        assertTarget( nameOrTarget );

        Class[] argTypes = new Class[]{ String.class };
        Constructor<? extends Permission> constructor;
        try {
            constructor = clazz.getDeclaredConstructor( argTypes );
        } catch ( NoSuchMethodException nsme ) {
            String msg = "Unable to find single argument String constructor for class [" + clazz.getName() + "].";
            throw new ConstructorAcquisitionException( msg, nsme );
        }

        Object[] args = new Object[]{ nameOrTarget };
        return instantiate( constructor, args );
    }

    public static Permission createPermission( Class<? extends Permission> clazz,
                                               String nameOrTarget,
                                               String actions ) throws ConstructorAcquisitionException {
        if ( actions != null ) {
            Class[] argTypes = new Class[]{ String.class, String.class };
            Constructor<? extends Permission> constructor;

            try {
                constructor = clazz.getDeclaredConstructor( argTypes );
            } catch ( NoSuchMethodException nsme ) {
                String msg = "Unable to find double String argument constructor on class [" + clazz.getName() + "].";
                throw new ConstructorAcquisitionException( msg );
            }

            // Instantiate permission with name and actions specified as attributes
            Object[] args = new Object[]{ nameOrTarget, actions };
            return instantiate( constructor, args );
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "actions method parameter was null.  Trying single String argument constructor..." );
            }
            return createPermission( clazz, nameOrTarget );
        }
    }

    public static Permission createPermission( String permissionClassName, String nameOrTarget ) {
        Class<? extends Permission> clazz = ClassUtils.forName( permissionClassName );
        return createPermission( clazz, nameOrTarget );
    }

    public static Permission createPermission( String permissionClassName,
                                               String nameOrTarget,
                                               String actions ) {
        Class<? extends Permission> clazz = ClassUtils.forName( permissionClassName );
        return createPermission( clazz, nameOrTarget, actions );
    }
}
