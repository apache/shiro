package org.jsecurity.authz.permission;

import org.jsecurity.authz.Permission;

/**
 *
 */
public class WildcardPermissionResolver implements PermissionResolver {

    public Permission resolvePermission(String permissionString) {
        return new WildcardPermission( permissionString );
    }                                  
}
