package org.jsecurity.ri.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.Constructor;
import java.security.Permission;

/**
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
