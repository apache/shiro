package org.jsecurity.web.servlet.authz;

import org.jsecurity.subject.Subject;

/**
 *
 */
public class PermissionRequirement implements AuthorizationRequirement {

    private String permission;

    public PermissionRequirement(String permission) {
        if( permission == null ) {
            throw new IllegalArgumentException( "Permission string cannot be null." );
        }
        this.permission = permission;
    }

    public boolean isSubjectAuthorized(Subject subject) {
        return subject.isPermitted( permission );
    }

}
