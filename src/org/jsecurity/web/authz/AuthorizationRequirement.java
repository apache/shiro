package org.jsecurity.web.authz;

import org.jsecurity.subject.Subject;

/**
 *
 */
public interface AuthorizationRequirement {

    boolean isSubjectAuthorized(Subject subject);

}
