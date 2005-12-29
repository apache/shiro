package org.jsecurity.ri.web.tags;

/**
 * @author Les Hazlewood
 */
public class LacksRoleTag extends RoleTag {

    public LacksRoleTag() {
    }

    protected boolean showTagBody( String roleName ) {
        boolean hasPermission = getAuthorizationContext().hasRole( roleName );
        return !hasPermission;
    }

}
