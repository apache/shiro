/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jsecurity;

import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.ThreadContext;

/**
 * Accesses the currently accessible <tt>Subject</tt> for the calling code depending on runtime environment.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class SecurityUtils {

    /**
     * ONLY used as a 'backup' in VM Singleton environments (that is, standalone environments), since the
     * ThreadContext should always be the primary source for Subject instances when possible.
     */
    private static SecurityManager securityManager;

    /**
     * Returns the currently accessible <tt>Subject</tt> available to the calling code depending on
     * runtime environment.
     * <p/>
     * This method is provided as a way of obtaining a <tt>Subject</tt> without having to resort to
     * implementation-specific methods.  It also allows the JSecurity team to change the underlying implementation of
     * this method in the future depending on requirements/updates without affecting your code that uses it.
     * <p/>
     * <b>Implementation Note:</b> This implementation expects a
     * {@link org.jsecurity.util.ThreadContext#getSecurityManager() thread-bound} or
     * {@link #setSecurityManager static VM singleton} {@code SecurityManager} to be accessible to this method at
     * runtime.  If not, an {@link IllegalStateException IllegalStateException} is thrown, indicating an incorrect
     * application configuration.
     *
     * @return the currently accessible <tt>Subject</tt> accessible to the calling code.
     *
     * @throws IllegalStateException if no {@link SecurityManager SecurityManager} instance is available to this method
     * at runtime, which is considered an invalid application configuration - a Subject should _always_ be available
     * to the caller.  If you encounter an exception when calling this method, ensure that the application's
     * {@code SecurityManager} is {@link org.jsecurity.util.ThreadContext#getSecurityManager() thread-bound} or a
     * {@link #setSecurityManager static VM singleton} prior to calling this method.
     */
    public static Subject getSubject() {
        Subject subject;
        SecurityManager securityManager = ThreadContext.getSecurityManager();
        if (securityManager != null) {
            subject = securityManager.getSubject();
        } else {
            subject = ThreadContext.getSubject();
            if (subject == null && SecurityUtils.securityManager != null) {
                //fall back to the VM singleton if one exists:
                subject = SecurityUtils.securityManager.getSubject();
            }
        }
        if ( subject == null ) {
            String msg = "No SecurityManager accessible to this method, either bound to the " +
                    ThreadContext.class.getName() + " or as a vm static singleton.  See the " +
                    SecurityUtils.class.getName() + ".getSubject() method JavaDoc for an explanation of expected " +
                    "environment configuration.";
            throw new IllegalStateException(msg);
        }
        return subject;
    }

    /**
     * Sets a VM (static) singleton SecurityManager, specifically for transparent use in the
     * {@link #getSubject() getSubject()} implementation.
     *
     * <p><b>This method call exists mainly for framework development support.  Application developers should rarely,
     * if ever, need to call this method.</b></p>
     *
     * <p>The JSecurity development team prefers that SecurityManager instances are non-static application singletons
     * and <em>not</em> VM static singletons.  Application singletons that do not use static memory require some sort
     * of application configuration framework to maintain the application-wide SecurityManager instance for you
     * (for example, Spring or EJB3 environments) such that the object reference does not need to be static.
     *
     * <p>In these environments, JSecurity acquires Subject data based on the currently executing Thread via its own
     * framework integration code, and this is the preferred way to use JSecurity.</p>
     *
     * <p>However in some environments, such as a standalone desktop application or Applets that do not use Spring or
     * EJB or similar config frameworks, a VM-singleton might make more sense (although the former is still preferred).</p>
     * In these environments, setting the SecurityManager via this method will automatically enable the
     * {@link #getSubject() getSubject()} call to function with little configuration.</p>
     *
     * <p>For example, in these environments, this will work:</p>
     *
     * <code>DefaultSecurityManager securityManager = new {@link org.jsecurity.mgt.DefaultSecurityManager DefaultSecurityManager}();<br/>
     * securityManager.setRealms( ... ); //one or more Realms<br/>
     * <b>SecurityUtils.setSecurityManager( securityManager );</b></code>
     *
     * <p>And then anywhere in the application code, the following call will return the application's Subject:</p>
     *
     * <p><code>Subject currentUser = SecurityUtils.getSubject()</code></p>
     *
     * <p>by calling the VM static {@link org.jsecurity.mgt.SecurityManager#getSubject() securityManager.getSubject()}
     * method.  Note that the underlying injected SecurityManager still needs to know how to acquire a Subject
     * instance for the calling code, which might mean from static memory, or a config file, or other
     * environment-specific means.</p>
     *
     * @param securityManager the securityManager instance to set as a VM static singleton.
     */
    public static void setSecurityManager(SecurityManager securityManager) {
        SecurityUtils.securityManager = securityManager;
    }

    /**
     * Returns the VM (static) singleton SecurityManager.
     *
     * <p>This method is <b>only used in rare occasions</b>.  Please read the {@link #setSecurityManager setSecurityManager}
     * JavaDoc for usage patterns.
     *
     * @return the VM (static) singleton SecurityManager, used only on rare occasions.
     */
    public static SecurityManager getSecurityManager() {
        return SecurityUtils.securityManager;
    }
}
