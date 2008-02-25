package org.jsecurity.web.authz;

import org.jsecurity.subject.Subject;

/**
 *
 */
public class AuthenticatedRequirement implements AuthorizationRequirement {

    public boolean isSubjectAuthorized(Subject subject) {
        return subject.isAuthenticated();
    }
}
