package org.jsecurity.web.session;

import org.jsecurity.session.Session;
import org.jsecurity.session.mgt.SessionManager;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since Apr 22, 2008 10:16:22 AM
 */
public interface WebSessionManager extends SessionManager {

    Session getSession( ServletRequest request, ServletResponse response );

}
