package org.jsecurity.authz;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * TODO class JavaDoc
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
        super( WILDCARD, WILDCARD );
    }


    public Set<String> getPossibleActions() {
        return possibleActions;
    }

    public boolean implies( Permission p ) {
        return true;    
    }
}
