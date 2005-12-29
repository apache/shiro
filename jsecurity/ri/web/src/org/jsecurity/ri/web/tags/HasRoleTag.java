package org.jsecurity.ri.web.tags;

/**
 * @author Les Hazlewood
 */
public class HasRoleTag extends RoleTag {

    public HasRoleTag(){}

    protected boolean showTagBody( String roleName ) {
        return getAuthorizationContext().hasRole( roleName );
    }

}
