package org.jsecurity.web.authz;

import org.jsecurity.subject.Subject;

/**
 *
 */
public class UserRequirement implements AuthorizationRequirement {

    public boolean isSubjectAuthorized(Subject subject) {
        return subject.getPrincipal() != null;
    }
}