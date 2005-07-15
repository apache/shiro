/*
 * Copyright (C) 2005 Les A. Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.session;

import java.io.Serializable;
import java.net.InetAddress;
import java.security.Principal;

/**
 * A SessionManager manages the creation, maintenance, and clean-up of Session objects.  A
 * Session is a data context associated with a single entity (user, 3rd party process, etc) that
 * communicates with the software system over a period of time.
 *
 * <p>All interaction with a secure system is done in the course of a Session, even if that
 * Session only exists over the course of a single method invocation.  Sessions are extremely
 * lightweight objects that have a managed lifecycle.
 *
 * @author Les Hazlewood
 */
public interface SessionManager {

    /**
     * Starts a new session within the system for the host with the specified originating IP
     * address.
     *
     * <p>Because an InetAddress is specified, secure access can also be restricted based
     * on system <em>location</em> as well as user principals if so desired (with some
     * caveats, as described below).
     *
     * <p>In web-based systems, this InetAddress can be retrieved from the
     * HttpSession.getRemoteAddr(), or in socket-based systems, it can be obtained via inspecting
     * the socket initiator's host IP.
     *
     * <p><b>Note</b> however, if clients to your system are on a
     * public network (as would be the case for a public web site), odds are high the clients can be
     * behind a NAT (Network Address Translation) router.  If so, all clients accessing your system
     * behind that router will have the same originating IP address.  If your system is configured
     * to allow only one session per IP, then the next request from a different NAT client will
     * fail and access will be denied for that client.  Just be aware that ip-based security
     * policies are best utilized in LAN or private WAN environments when you can be sure clients
     * will not share IPs or be behind such NAT routers.
     *
     * @param originatingHost the originating host InetAddress of the external party
     * (user, 3rd party product, etc) that is attempting to interact with the system.
     * 
     * @return the system identifier of the newly created session.
     */
    Serializable start( InetAddress originatingHost );

    /**
     * Returns whether or not the session identified by <code>sessionId</code> has been
     * authenticated (e.g. a user has logged in to the system during the session).
     *
     * @param sessionId the session Id of the session to verify.
     *
     * @return true if the session has been authenticated (i.e. 'logged in'), false otherwise.
     */
    boolean isAuthenticated( Serializable sessionId );

    boolean isStopped( Serializable sessionId );

    /**
     * Updates the last accessed time of the session identified by <code>sessionId</code>.  This
     * can be used to explicitly ensure that a session does not time out.
     *
     * <p>This method is particularly useful when supporting rich-client applications such as
     * Java Web Start apps or Java applets.  It is possible in a rich-client environment that
     * a user continuously interacts with the client-side application without a server-side
     * method call ever being invoked.  If this happens over a long enough period of time, and
     * the server is configured to expire sessions, the user's session could time-out.
     *
     * <p>In the above example though, the user's session is still considered valid because the user
     * is actively "using" the application the whole time.  But because no server-side method
     * calls are invoked,
     * there is no way for the server to know if the user is sitting idle or not (so it must
     * assume so to maintain security).  This method could be invoked by the rich-client
     * application code during those instances to ensure that the next time a server-side
     * invocation is required, the user's session would not have accidentally expired.
     *
     * <p>How often this would occur is entirely dependent upon the application and is based on
     * variables such as session timeout configuration, usage characteristics of the
     * client application, network utilization and application server performance.
     *
     * @param sessionId the id of the session to update.
     */
    void touch( Serializable sessionId );

    /**
     * Returns the principal of the authenticated user or entity that initiated the session
     * identified by <code>sessionId</code>, if known.  A session is usually created before an
     * authc takes place, so this method may return <code>null</code> if the principal
     * is unknown or the session hasn't yet been authenticated.
     *
     * <p>For example, in a web-based system, just visiting the first web page usually initiates a
     * session.  But if that web page happens to be the log-in page, the session that was created
     * hasn't yet been authenticated.  In this case, there is no principal (i.e. username
     * in this case) yet associated with the session.
     *
     * <p>However, if the user submits the log-in form and is successful, this method could
     * then be called to get the principal (username) of that person.
     *
     * <p>The principal itself can be any valid Java security principal.  In the above example, it
     * was a username.  In other systems (especially RDBMS-based ones) it is usually an
     * entity/user id such as a UUID or Integer.
     *
     * @return the identifying principal of the user or entity that authenticated this session,
     * or <code>null</code> if this session hasn't yet been authenticated.
     */
    Principal getPrincipal( Serializable sessionId );


    /**
     * Returns the IP address of the host where the session was started, if known.  If
     * no IP was specified when starting the session, this method returns <code>null</code>
     * @param sessionId the id of the session to query.
     *
     * @return the ip address of the host where the session originated, if known.  If unknown,
     * this method returns <code>null</code>.
     *
     * @see #start( InetAddress originatingHost ) start( InetAddress originatingHost )
     */
    InetAddress getHostAddress( Serializable sessionId );


}
