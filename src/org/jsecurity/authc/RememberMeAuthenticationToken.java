/*
 * Copyright (C) 2005-2008 Les Hazlewood
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
package org.jsecurity.authc;

/**
 * An <tt>AuthenticationToken</tt> that indicates if the user wishes their identity to be remembered across sessions.
 *
 * <p>Please note however that when a new session is created for the corresponding user, that user's identity is
 * remembered, but they are <em>NOT</em> considered authenticated:
 *
 * <p>Authentication is the process of proving you are who you say you are.  In a RememberMe scenario, a remembered
 * identity gives the system an idea who that person probably is, but in reality, has no way of guaranteeing the
 * remembered identity <em>really</em> is that user.
 *
 * <p>So, although many parts of the application can perform user-specific logic, such as customized views, it should
 * never perform security-sensitive operations until the user has actually executed a proper authentication attempt.
 *
 * <p>We see this paradigm all over the web, and we'll use <tt>amazon.com</tt> as an example:
 *
 * <p>When you visit Amazon.com and perform a login and ask it to 'remember me', it will set a cookie with your
 * identity.  If you don't log out and your session expires, and come back, say the next day, Amazon still knows
 * who you <em>probably</em> are.</p>
 *
 * <p>BUT, if you try to do some sensitive operations, such as access your account's billing data, Amazon forces you
 * to do an actual log-in, requiring your username and password.
 *
 * <p>This is because, although amazon.com assumed your identity from 'remember me', the only way to really
 * guarantee you are who you say you are (and therefore able to access sensitive account data), is for you to
 * perform an actual authentication.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public interface RememberMeAuthenticationToken extends AuthenticationToken {

    /**
     * Returns <tt>true</tt> if the submitting user wishes their identity (principal(s)) to be remembered
     * across sessions, <tt>false</tt> otherwise.
     *
     * <p>Please see the class-level JavaDoc for what 'remember me' vs. 'authenticated' means - they are semantically 
     * different.
     *
     * @return <tt>true</tt> if the submitting user wishes their identity (principal(s)) to be remembered
     * across sessions, <tt>false</tt> otherwise.
     */
    boolean isRememberMe();

}
