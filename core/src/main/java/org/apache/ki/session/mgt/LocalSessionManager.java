package org.apache.ki.session.mgt;

import org.apache.ki.session.Session;

/**
 * A {@code SessionManager} that is available in a local VM only.  It is not intended to be accessible
 * in remoting scenarios.
 *
 * @author Les Hazlewood
 * @since Mar 26, 2009 2:34:44 PM
 */
public interface LocalSessionManager extends SessionManager {

    /**
     * Returns the currently accessible {@link Session} based on the runtime environment.  This is mostly
     * returned from a ThreadLocal, static memory or based on thread-bound Request/Response pair in a Web
     * environment.
     *
     * @return the currently accessible {@link Session} based on the runtime environment.
     */
    Session getCurrentSession();


}
