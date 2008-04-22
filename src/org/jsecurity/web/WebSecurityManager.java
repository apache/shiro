package org.jsecurity.web;

import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since Apr 22, 2008 10:32:59 AM
 */
public interface WebSecurityManager extends SecurityManager {

    Subject getSubject( ServletRequest request, ServletResponse response );

}
