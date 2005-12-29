package org.jsecurity.ri.web.tags;

import java.security.Permission;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class LacksPermissionTag extends PermissionTag {

    public LacksPermissionTag() {
    }

    protected boolean showTagBody( Permission p ) {
        boolean permitted = getAuthorizationContext().hasPermission( p );
        return !permitted;
    }

}
