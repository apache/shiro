package org.jsecurity.web.authz;

import org.jsecurity.subject.Subject;

/**
 *
 */
public class RoleRequirement implements AuthorizationRequirement {

    private String role;

    public RoleRequirement(String role) {
        if( role == null ) {
            throw new IllegalArgumentException( "Role name cannot be null." );
        }
        this.role = role;
    }

    public boolean isSubjectAuthorized(Subject subject) {
        return subject.hasRole( role );
    }

}
