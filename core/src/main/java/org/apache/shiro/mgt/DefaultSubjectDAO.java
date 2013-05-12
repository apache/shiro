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
package org.apache.shiro.mgt;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;

/**
 * Default {@code SubjectDAO} implementation that stores Subject state in the Subject's Session by default (but this
 * can be disabled - see below).  The Subject instance
 * can be re-created at a later time by first acquiring the associated Session (typically from a
 * {@link org.apache.shiro.session.mgt.SessionManager SessionManager}) via a session ID or session key and then
 * building a {@code Subject} instance from {@code Session} attributes.
 * <h2>Controlling how Sessions are used</h2>
 * Whether or not a {@code Subject}'s {@code Session} is used or not to persist its own state is controlled on a
 * <em>per-Subject</em> basis as determined by the configured
 * {@link #setSessionStorageEvaluator(SessionStorageEvaluator) sessionStorageEvaluator}.
 * The default {@code Evaluator} is a {@link DefaultSessionStorageEvaluator}, which supports enabling or disabling
 * session usage for Subject persistence at a global level for all subjects (and defaults to allowing sessions to be
 * used).
 * <h3>Disabling Session Persistence Entirely</h3>
 * Because the default {@code SessionStorageEvaluator} instance is a {@link DefaultSessionStorageEvaluator}, you
 * can disable Session usage for Subject state entirely by configuring that instance directly, e.g.:
 * <pre>
 *     ((DefaultSessionStorageEvaluator)sessionDAO.getSessionStorageEvaluator()).setSessionStorageEnabled(false);
 * </pre>
 * or, for example, in {@code shiro.ini}:
 * <pre>
 *     securityManager.subjectDAO.sessionStorageEvaluator.sessionStorageEnabled = false
 * </pre>
 * but <b>note:</b> ONLY do this your
 * application is 100% stateless and you <em>DO NOT</em> need subjects to be remembered across remote
 * invocations, or in a web environment across HTTP requests.
 * <h3>Supporting Both Stateful and Stateless Subject paradigms</h3>
 * Perhaps your application needs to support a hybrid approach of both stateful and stateless Subjects:
 * <ul>
 * <li>Stateful: Stateful subjects might represent web end-users that need their identity and authentication
 * state to be remembered from page to page.</li>
 * <li>Stateless: Stateless subjects might represent API clients (e.g. REST clients) that authenticate on every
 * request, and therefore don't need authentication state to be stored across requests in a session.</li>
 * </ul>
 * To support the hybrid <em>per-Subject</em> approach, you will need to create your own implementation of the
 * {@link SessionStorageEvaluator} interface and configure it via the
 * {@link #setSessionStorageEvaluator(SessionStorageEvaluator)} method, or, with {@code shiro.ini}:
 * <pre>
 *     myEvaluator = com.my.CustomSessionStorageEvaluator
 *     securityManager.subjectDAO.sessionStorageEvaluator = $myEvaluator
 * </pre>
 * <p/>
 * Unless overridden, the default evaluator is a {@link DefaultSessionStorageEvaluator}, which enables session usage for
 * Subject state by default.
 *
 * @see #isSessionStorageEnabled(org.apache.shiro.subject.Subject)
 * @see SessionStorageEvaluator
 * @see DefaultSessionStorageEvaluator
 * @since 1.2
 */
public class DefaultSubjectDAO implements SubjectDAO {

    private static final Logger log = LoggerFactory.getLogger(DefaultSubjectDAO.class);

    /**
     * Evaluator that determines if a Subject's session may be used to store the Subject's own state.
     */
    private SessionStorageEvaluator sessionStorageEvaluator;

    public DefaultSubjectDAO() {
        //default implementation allows enabling/disabling session usages at a global level for all subjects:
        this.sessionStorageEvaluator = new DefaultSessionStorageEvaluator();
    }

    /**
     * Determines if the subject's session will be used to persist subject state or not.  This implementation
     * merely delegates to the internal {@link SessionStorageEvaluator} (a
     * {@code DefaultSessionStorageEvaluator} by default).
     *
     * @param subject the subject to inspect to determine if the subject's session will be used to persist subject
     *                state or not.
     * @return {@code true} if the subject's session will be used to persist subject state, {@code false} otherwise.
     * @see #setSessionStorageEvaluator(SessionStorageEvaluator)
     * @see DefaultSessionStorageEvaluator
     */
    protected boolean isSessionStorageEnabled(Subject subject) {
        return getSessionStorageEvaluator().isSessionStorageEnabled(subject);
    }

    /**
     * Returns the {@code SessionStorageEvaluator} that will determine if a {@code Subject}'s state may be persisted in
     * the Subject's session.  The default instance is a {@link DefaultSessionStorageEvaluator}.
     *
     * @return the {@code SessionStorageEvaluator} that will determine if a {@code Subject}'s state may be persisted in
     *         the Subject's session.
     * @see DefaultSessionStorageEvaluator
     */
    public SessionStorageEvaluator getSessionStorageEvaluator() {
        return sessionStorageEvaluator;
    }

    /**
     * Sets the {@code SessionStorageEvaluator} that will determine if a {@code Subject}'s state may be persisted in
     * the Subject's session. The default instance is a {@link DefaultSessionStorageEvaluator}.
     *
     * @param sessionStorageEvaluator the {@code SessionStorageEvaluator} that will determine if a {@code Subject}'s
     *                                state may be persisted in the Subject's session.
     * @see DefaultSessionStorageEvaluator
     */
    public void setSessionStorageEvaluator(SessionStorageEvaluator sessionStorageEvaluator) {
        this.sessionStorageEvaluator = sessionStorageEvaluator;
    }

    /**
     * Saves the subject's state to the subject's {@link org.apache.shiro.subject.Subject#getSession() session} only
     * if {@link #isSessionStorageEnabled(Subject) sessionStorageEnabled(subject)}.  If session storage is not enabled
     * for the specific {@code Subject}, this method does nothing.
     * <p/>
     * In either case, the argument {@code Subject} is returned directly (a new Subject instance is not created).
     *
     * @param subject the Subject instance for which its state will be created or updated.
     * @return the same {@code Subject} passed in (a new Subject instance is not created).
     */
    public Subject save(Subject subject) {
        if (isSessionStorageEnabled(subject)) {
            saveToSession(subject);
        } else {
            log.trace("Session storage of subject state for Subject [{}] has been disabled: identity and " +
                    "authentication state are expected to be initialized on every request or invocation.", subject);
        }

        return subject;
    }

    /**
     * Saves the subject's state (it's principals and authentication state) to its
     * {@link org.apache.shiro.subject.Subject#getSession() session}.  The session can be retrieved at a later time
     * (typically from a {@link org.apache.shiro.session.mgt.SessionManager SessionManager} to be used to recreate
     * the {@code Subject} instance.
     *
     * @param subject the subject for which state will be persisted to its session.
     */
    protected void saveToSession(Subject subject) {
        //performs merge logic, only updating the Subject's session if it does not match the current state:
        mergePrincipals(subject);
        mergeAuthenticationState(subject);
    }

    private static boolean isEmpty(PrincipalCollection pc) {
        return pc == null || pc.isEmpty();
    }

    /**
     * Merges the Subject's current {@link org.apache.shiro.subject.Subject#getPrincipals()} with whatever may be in
     * any available session.  Only updates the Subject's session if the session does not match the current principals
     * state.
     *
     * @param subject the Subject for which principals will potentially be merged into the Subject's session.
     */
    protected void mergePrincipals(Subject subject) {
        //merge PrincipalCollection state:

        PrincipalCollection currentPrincipals = null;

        //SHIRO-380: added if/else block - need to retain original (source) principals
        //This technique (reflection) is only temporary - a proper long term solution needs to be found,
        //but this technique allowed an immediate fix that is API point-version forwards and backwards compatible
        //
        //A more comprehensive review / cleaning of runAs should be performed for Shiro 1.3 / 2.0 +
        if (subject.isRunAs() && subject instanceof DelegatingSubject) {
            try {
                Field field = DelegatingSubject.class.getDeclaredField("principals");
                field.setAccessible(true);
                currentPrincipals = (PrincipalCollection)field.get(subject);
            } catch (Exception e) {
                throw new IllegalStateException("Unable to access DelegatingSubject principals property.", e);
            }
        }
        if (currentPrincipals == null || currentPrincipals.isEmpty()) {
            currentPrincipals = subject.getPrincipals();
        }

        Session session = subject.getSession(false);

        if (session == null) {
            if (!isEmpty(currentPrincipals)) {
                session = subject.getSession();
                session.setAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY, currentPrincipals);
            }
            // otherwise no session and no principals - nothing to save
        } else {
            PrincipalCollection existingPrincipals =
                    (PrincipalCollection) session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);

            if (isEmpty(currentPrincipals)) {
                if (!isEmpty(existingPrincipals)) {
                    session.removeAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);
                }
                // otherwise both are null or empty - no need to update the session
            } else {
                if (!currentPrincipals.equals(existingPrincipals)) {
                    session.setAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY, currentPrincipals);
                }
                // otherwise they're the same - no need to update the session
            }
        }
    }

    /**
     * Merges the Subject's current authentication state with whatever may be in
     * any available session.  Only updates the Subject's session if the session does not match the current
     * authentication state.
     *
     * @param subject the Subject for which principals will potentially be merged into the Subject's session.
     */
    protected void mergeAuthenticationState(Subject subject) {

        Session session = subject.getSession(false);

        if (session == null) {
            if (subject.isAuthenticated()) {
                session = subject.getSession();
                session.setAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY, Boolean.TRUE);
            }
            //otherwise no session and not authenticated - nothing to save
        } else {
            Boolean existingAuthc = (Boolean) session.getAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY);

            if (subject.isAuthenticated()) {
                if (existingAuthc == null || !existingAuthc) {
                    session.setAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY, Boolean.TRUE);
                }
                //otherwise authc state matches - no need to update the session
            } else {
                if (existingAuthc != null) {
                    //existing doesn't match the current state - remove it:
                    session.removeAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY);
                }
                //otherwise not in the session and not authenticated - no need to update the session
            }
        }
    }

    /**
     * Removes any existing subject state from the Subject's session (if the session exists).  If the session
     * does not exist, this method does not do anything.
     *
     * @param subject the subject for which any existing subject state will be removed from its session.
     */
    protected void removeFromSession(Subject subject) {
        Session session = subject.getSession(false);
        if (session != null) {
            session.removeAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY);
            session.removeAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);
        }
    }

    /**
     * Removes any existing subject state from the subject's session (if the session exists).
     *
     * @param subject the Subject instance for which any persistent state should be deleted.
     */
    public void delete(Subject subject) {
        removeFromSession(subject);
    }
}
