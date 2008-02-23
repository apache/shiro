package org.jsecurity.web.servlet.authz;

import org.jsecurity.subject.Subject;

/**
 *
 */
public class AuthorizedRequirement implements AuthorizationRequirement {

    public boolean isSubjectAuthorized(Subject subject) {
        return subject.isAuthenticated();
    }
}
