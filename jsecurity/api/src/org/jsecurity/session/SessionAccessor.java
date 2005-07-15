package org.jsecurity.session;

import java.net.InetAddress;
import java.io.Serializable;

/**
 * Created by IntelliJ IDEA. User: lhazlewood Date: Jul 15, 2005 Time: 10:33:35 AM To change this
 * template use File | Settings | File Templates.
 */
public interface SessionAccessor {

    Session start();

    Session start( InetAddress hostAddress );

    Session getSession( Serializable sessionId );

}
