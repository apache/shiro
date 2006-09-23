/*
 * Copyright (C) 2005 Jeremy Haile, Les Hazlewood
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

package org.jsecurity.context;

import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.session.Session;

/**
 * <p>The <code>SecurityContext</code> is the application programmer's entry point into the
 * JSecurity API.  It is a component that aggregates authentication (log-in), authorization
 * (access control), and {@link org.jsecurity.session.Session session} management for a single
 * 'user'.  The <tt>SecurityContext</tt> should be the most frequently used
 * JSecurity component when programming - most other classes and interfaces exist to support the
 * <tt>SecurityContext</tt> or are provided for application configuration.
 *
 * <p>The definition of a 'user' is defined by your application - it is most usually a human being
 * that uses the application, but can just as well be a 3rd party application making remote calls,
 * a daemon process, or any other subject that interacts with the application.
 *
 * <p>Note that this interface extends the {@link AuthorizationContext} interface.  Because a
 * <tt>SecurityContext</tt> exists per user, regardless if that user is logged in or not, these
 * inherited methods don't mean much if the user hasn't logged in.  This is because a system
 * can only determine authorization behavior (access control decisions) once the user's identity
 * has been validated (i.e. they have logged in).
 *
 * <p>So, most implementations of <tt>SecurityContext</tt> will always return
 * <tt>null</tt> or <tt>false</tt> or throw exceptions (dependong on implementation)
 * for the corresponding  <tt>AuthorizationContext</tt> methods until after the user is
 * authenticated.  Therefore, it is not enough to call an <tt>AuthorizationContext</tt> method to
 * determine if the user has logged in or not.  For that purpose, the
 * {@link #isAuthenticated()} method is provided to accurately determine this information.
 *
 * <p><b>Implementation Notes</b>: Also note that this interface extends the {@link Authenticator}
 * interface for convenience purposes as well.  But because there is typically a single
 * <tt>Authenticator</tt> per application (although this is really up to the application
 * configuration and not a requirement), the <tt>SecurityContext</tt> typically acts as a proxy to
 * the application's 'real' <tt>Authenticator</tt>.  This allows a programmer to do things like
 * this:
 *
 * <pre><code>
 * //get security context from framework or implementation-specifc manner:
 * SecurityContext secCtx = getSecurityContext();
 * //login:
 * UsernamePasswordToken token = new UsernamePasswordToken( aUsername, aPassword );
 * secCtx.authenticate( token );
 * //no exceptions thrown, user is logged in - check if they can do something special:
 * if ( secCtx.implies( new SoupPermission( "Chicken Noodle", "placeOrder" ) ) {
 *     //dispense delicious goodness
 * } else {
 *     alert( "No soup for you!" );
 * }</pre></code>
 *
 * @since 0.1

 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface SecurityContext extends Authenticator, AuthorizationContext {

    /**
     * Returns <tt>true</tt> if the user represented by this <tt>SecurityContxt</tt> is currently
     * logged-in to the system, <tt>false</tt> otherwise.
     * @return <tt>true</tt> if the user represented by this <tt>SecurityContxt</tt> is currently
     * logged-in to the system, <tt>false</tt> otherwise.
     */
    public abstract boolean isAuthenticated();

    /**
     * Returns the user's application <tt>Session</tt>, or <tt>null</tt> if there is no
     * <tt>Session</tt> associated with the user..
     *
     * @return the user's application <tt>Session</tt>, or <tt>null</tt>
     * if there is no session associated with the user.
     */
    public abstract Session getSession();

    /**
     * Invalidates and removes any entities (such as a {@link Session Session} and authorization
     * context associated with the user represented by this <tt>SecurityContext</tt>.
     *
     * @see #getSession
     */
    public abstract void invalidate();
}