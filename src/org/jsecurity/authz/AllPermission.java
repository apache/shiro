package org.jsecurity.authz;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * An all <tt>AllPermission</tt> instance is one that always implies any other permission; that is, its
 * {@link #implies implies} method always returns <tt>true</tt>.
 *
 * <p>You should be very careful about the users, roles, and/or groups to which you assign this permission since
 * those respective entities will have the ability to do anything.  As such, an instance of this class
 * is typically only assigned only to "root" or "administrator" users or roles.
 *
 * @author Les Hazlewood
 */
public class AllPermission extends AbstractPermission {

    private static final LinkedHashSet<String> possibleActions = initPossibleActionsSet();

    private static LinkedHashSet<String> initPossibleActionsSet() {
        LinkedHashSet<String> possibleActions = new LinkedHashSet<String>(1);
        possibleActions.add( WILDCARD );
        return possibleActions;
    }

    public AllPermission() {
        super( WILDCARD, possibleActions );
    }

    public Set<String> getPossibleActions() {
        return possibleActions;
    }

    public boolean implies( Permission p ) {
        return true;    
    }
}
