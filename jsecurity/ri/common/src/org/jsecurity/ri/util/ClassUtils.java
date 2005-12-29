package org.jsecurity.ri.util;

/**
 * @author Les Hazlewood
 */
public class ClassUtils {

    public static ClassLoader getDefaultClassLoader() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if ( cl == null ) {
            cl = ClassUtils.class.getClassLoader();
        }
        return cl;
    }

    public static Class forName( String fullyQualified ) throws UnknownClassException {
        ClassLoader cl = getDefaultClassLoader();
        try {
            return cl.loadClass( fullyQualified );
        } catch ( ClassNotFoundException e ) {
            String msg = "Unable to load class name [" + fullyQualified + "] from ClassLoader [" +
                cl + "]";
            throw new UnknownClassException( msg, e );
        }
    }

}
