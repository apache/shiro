/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
     *
     * <p>This method is provided as a way of obtaining a <tt>Subject</tt> without having to resort to
     * implementation-specific methods.  It also allows the JSecurity team to change the underlying implementation of
     * this method in the future depending on requirements/updates without affecting your code that uses it.
     *
     * @return the currently accessible <tt>Subject</tt> accessible to the calling code.
     */
    public static Subject getSubject() {
        Subject subject = ThreadContext.getSubject();
        //try from VM singleton if there is one:
        if (subject == null && SecurityUtils.securityManager != null) {
            subject = SecurityUtils.securityManager.getSubject();
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
     * <pre>       DefaultSecurityManager securityManager = new {@link org.jsecurity.mgt.DefaultSecurityManager DefaultSecurityManager}();
     * securityManager.setRealms( ... ); //one or more Realms
     * securityManager.init();
     * <b>SecurityUtils.setSecurityManager( securityManager );</b></pre>
     *
     * <p>And then anywhere in the application code, the following call will return the application's Subject:</p>
     *
     * <pre>Subject currentUser = SecurityUtils.getSubject()</pre>
     *
     * <p>by calling the VM static {@link org.jsecurity.mgt.SecurityManager#getSubject() securityManager.getSubject()}
     * method.  Note that the underlying injected SecurityManager still needs to know how to acquire a Subject
     * instance for the calling code, which might mean from static memory, or a config file, or other
     * environment-specific means.</p>
     *
     * @param securityManager
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
