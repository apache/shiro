package org.jsecurity.util;

/**
 * Set of static helper method used to assert conditions.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class AssertUtils {

    /**
     * Prevent instantiation.
     */
    private AssertUtils() {}


    public static void notNull(Object obj) {
        if( obj == null ) {
            throw new IllegalArgumentException( "Argument cannot be null." );
        }
    }
}
