package org.jsecurity.ri.web.tags;

import java.security.Permission;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class HasPermissionTag extends PermissionTag {

    public HasPermissionTag() {
    }

    protected boolean showTagBody( Permission p ) {
        return getAuthorizationContext().hasPermission( p );
    }

}
