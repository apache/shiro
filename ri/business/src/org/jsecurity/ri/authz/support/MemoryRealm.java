package org.jsecurity.ri.authz.support;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.ri.authz.Realm;

import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * A simple implementation of the {@link Realm} interface that holds a mapping between
 * principals and an {@link AuthorizationInfo} object associated with that principal.
 *
 * todo All of the methods in this class will throw a NPE if the principal in question does not have any authorization info configured
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class MemoryRealm implements Realm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * A mapping between a user's principal and the user's authorization information.
     */
    private Map<Principal, AuthorizationInfo> authorizationInfoMap;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    public MemoryRealm(Map<Principal, AuthorizationInfo> authorizationInfoMap) {
        this.authorizationInfoMap = authorizationInfoMap;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public boolean hasRole(Principal subjectIdentifier, String roleIdentifier) {
        AuthorizationInfo info = authorizationInfoMap.get( subjectIdentifier );
        return info.hasRole( roleIdentifier );
    }

    public boolean[] hasRoles(Principal subjectIdentifier, List<String> roleIdentifiers) {
        AuthorizationInfo info = authorizationInfoMap.get( subjectIdentifier );
        return info.hasRoles( roleIdentifiers );
    }

    public boolean hasAllRoles(Principal subjectIdentifier, Collection<String> roleIdentifiers) {
        AuthorizationInfo info = authorizationInfoMap.get( subjectIdentifier );
        return info.hasAllRoles( roleIdentifiers );
    }

    public boolean isPermitted(Principal subjectIdentifier, Permission permission) {
        AuthorizationInfo info = authorizationInfoMap.get( subjectIdentifier );
        return info.implies( permission );
    }

    public boolean[] isPermitted(Principal subjectIdentifier, List<Permission> permissions) {
        AuthorizationInfo info = authorizationInfoMap.get( subjectIdentifier );
        return info.implies( permissions );
    }

    public boolean isPermittedAll(Principal subjectIdentifier, Collection<Permission> permissions) {
        AuthorizationInfo info = authorizationInfoMap.get( subjectIdentifier );
        return info.impliesAll( permissions );
    }

    public void checkPermission(Principal subjectIdentifier, Permission permission) throws AuthorizationException {
        AuthorizationInfo info = authorizationInfoMap.get( subjectIdentifier );
        info.checkPermission( permission );
    }

    public void checkPermissions(Principal subjectIdentifier, Collection<Permission> permissions) throws AuthorizationException {
        AuthorizationInfo info = authorizationInfoMap.get( subjectIdentifier );
        info.checkPermissions( permissions );
    }
}
