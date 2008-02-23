package org.jsecurity.web.servlet.authz;

import org.jsecurity.subject.Subject;

/**
 *
 */
public interface AuthorizationRequirement {

    boolean isSubjectAuthorized(Subject subject);

}
