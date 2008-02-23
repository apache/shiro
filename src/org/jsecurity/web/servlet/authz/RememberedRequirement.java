package org.jsecurity.web.servlet.authz;

import org.jsecurity.subject.Subject;

/**
 *
 */
public class RememberedRequirement implements AuthorizationRequirement {

    public boolean isSubjectAuthorized(Subject subject) {
        return subject.getPrincipal() != null;
    }
}