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
package org.jsecurity.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.Permission;

import java.lang.reflect.Constructor;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @since 0.1
 * @author Les Hazlewood
 */
public class PermissionUtils {

    private static final String PERMISSIONS_DELIMITER = ";";
    private static final String PERMISSION_PART_DELIMITER = ",";

    protected static transient final Log log = LogFactory.getLog( PermissionUtils.class );

    private static String strip( String in ) {
        String out = null;
        if ( in != null ) {
            out = in.trim();
            if ( out.equals( "" ) ) {
                out = null;
            }
        }
        return out;
    }

    private static Class[] getTypes( Object[] args ) {
        if ( args == null || args.length == 0 ) {
            return null;
        } else {
            Class[] types = new Class[args.length];
            for( int i = 0; i < args.length; i++ ) {
                Object arg = args[i];
                types[i] = ( arg != null ? arg.getClass() : null );
            }
            return types;
        }
    }

    private static Object[] toArray( String arg1, String arg2 ) {
        Object[] array = null;
        if ( arg2 != null ) {
            array = new Object[]{ arg1, arg2 };
        } else {
            if ( arg1 != null ) {
                array = new Object[]{ arg1 };
            } else {
                array = null;
            }
        }
        return array;
    }

    public static Permission createPermissino( String permissionFullyQualifiedClassName ) {
        return createPermission( permissionFullyQualifiedClassName, null, null );
    }
    
    public static Permission createPermission( String permissionClassName, String nameOrTarget ) {
        return createPermission( permissionClassName, nameOrTarget, null );
    }

    public static Permission createPermission( String permissionClassName,
                                               String nameOrTarget,
                                               String actions ) {
        //noinspection unchecked
        Class<? extends Permission> clazz = ClassUtils.forName( permissionClassName );
        return createPermission( clazz, nameOrTarget, actions );
    }

    /**
     * Creates a <tt>Permission</tt> instance using the default no-argument constructor.
     * @param clazz the <tt>Permission</tt> class.
     * @return the newly instantiated <tt>Permission</tt> instance.
     */
    public static Permission createPermission( Class<? extends Permission> clazz ) {
        return createPermission( clazz, null, null );
    }

    public static Permission createPermission( Class<? extends Permission> clazz, String nameOrTarget )
        throws UnavailableConstructorException {
        return createPermission( clazz, nameOrTarget, null );
    }

    public static Permission createPermission( Class<? extends Permission> clazz,
                                               String nameOrTarget,
                                               String commaDelimitedActions ) throws UnavailableConstructorException {

        Permission instance = null;

        String value = strip( nameOrTarget );
        String actions = strip( commaDelimitedActions );

        Object[] ctorArgs = toArray( value, actions );

        if ( ctorArgs == null ) {
            instance = (Permission)ClassUtils.newInstance( clazz );
        } else {
            Constructor<? extends Permission> constructor;
            Class[] argTypes = getTypes( ctorArgs );
            try {
                constructor = clazz.getDeclaredConstructor( argTypes );
            } catch ( NoSuchMethodException nsme ) {
                String msg = "Unable to find " + ( argTypes.length == 2 ? "double" : "single" ) + 
                    " String argument constructor on class [" + clazz.getName() + "].";
                throw new UnavailableConstructorException( msg );
            }

            instance = (Permission)ClassUtils.instantiate( constructor, ctorArgs );
        }

        return instance;
    }

    protected static Set<String> toSet( String delimited, String delimiter ) {
        if ( delimited == null || delimited.trim().equals( "" ) ) {
            return null;
        }

        Set<String> values = new LinkedHashSet<String>();
        String[] rolenamesArray = delimited.split( delimiter );
        for( String s : rolenamesArray ) {
            String trimmed = s.trim();
            if ( !trimmed.equals( "" ) ) {
                values.add( trimmed );
            }
       }

       return values;
    }

    public static Permission fromDefinition( String permDef ) {

        String def = strip( permDef );
        if ( def == null ) {
            return null;
        }

        //split into respective components:
        String classname = null;
        String target = null;
        String actions = null;

        String[] parts =  def.split( PERMISSION_PART_DELIMITER, 3 );
        if ( parts.length >= 3 ) {
            actions = strip( parts[2] );
        }
        if ( parts.length >= 2 ) {
            target = strip( parts[1] );
        }
        if ( parts.length >= 1 ) {
            classname = strip( parts[0] );
        }

        return createPermission( classname, target, actions );
    }

    public static Set<Permission> fromDefinitions( String permissionDefinitions ) {

        String defs = strip( permissionDefinitions );

        if ( defs == null ) {
            return null;
        }

        Set<String> defnSet = toSet( permissionDefinitions, PERMISSIONS_DELIMITER );
        Set<Permission> perms = new LinkedHashSet<Permission>( defnSet.size() );

        for( String permDef : defnSet ) {
            perms.add( fromDefinition( permDef ) );
        }

        return perms;
    }
}
