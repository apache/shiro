/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.mgt

import org.apache.shiro.session.Session
import org.apache.shiro.subject.PrincipalCollection
import org.apache.shiro.subject.Subject
import org.apache.shiro.subject.support.DefaultSubjectContext
import org.apache.shiro.subject.support.DelegatingSubject
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link DefaultSubjectDAO} implementation.
 *
 * @since 1.2
 */
class DefaultSubjectDAOTest {

    @Test
    void testIsSessionStorageEnabledDefault() {
        def dao = new DefaultSubjectDAO()
        assertTrue dao.sessionStorageEvaluator instanceof DefaultSessionStorageEvaluator
        assertTrue dao.isSessionStorageEnabled(null)
    }

    @Test
    void testIsSessionStorageEnabledDefaultSubject() {
        def dao = new DefaultSubjectDAO()

        def subject = createStrictMock(Subject)

        expect(subject.getSession(false)).andReturn null

        replay subject

        assertTrue dao.isSessionStorageEnabled(subject)

        verify subject
    }

    @Test
    void testCustomSessionStorageEvaluator() {
        def dao = new DefaultSubjectDAO()
        def subject = createMock(Subject)
        def evaluator = createStrictMock(SessionStorageEvaluator)
        dao.sessionStorageEvaluator = evaluator

        expect(evaluator.isSessionStorageEnabled(same(subject))).andReturn true

        replay subject, evaluator

        assertTrue dao.isSessionStorageEnabled(subject)

        verify subject, evaluator
    }

    @Test
    void testDeleteWithoutSession() {
        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)

        expect(subject.getSession(false)).andReturn null

        replay subject

        dao.delete(subject)

        verify subject
    }

    @Test
    void testDeleteWithSession() {
        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)

        expect(subject.getSession(false)).andReturn(session)
        expect(session.removeAttribute(eq(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY))).andReturn null
        expect(session.removeAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY))).andReturn null

        replay subject, session

        dao.delete(subject)

        verify subject, session
    }

    /**
     * Ensures that when save is called and session storage is disabled, that the subject is never asked for its session.
     */
    @Test
    void testSaveWhenSessionStorageIsDisabled() {
        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)

        expect(subject.getSession(false)).andReturn null

        //turn off session storage:
        ((DefaultSessionStorageEvaluator)dao.sessionStorageEvaluator).sessionStorageEnabled = false

        replay subject

        Subject saved = dao.save(subject)

        assertSame saved, subject

        verify subject
    }

    /**
     * Tests the case when the save method is called but the Subject does not yet have any associated
     * principals or authentication state or even a session.  In this case, the session should never be created.
     */
    @Test
    void testSaveWithoutSessionOrPrincipalsOrAuthentication() {
        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)

        expect(subject.getSession(false)).andReturn null

        expect(subject.isRunAs()).andReturn false
        expect(subject.principals).andReturn null
        expect(subject.getSession(false)).andReturn(null).anyTimes()
        expect(subject.authenticated).andReturn false

        replay subject, session

        dao.save(subject)

        verify subject, session
    }

    // BEGIN: mergePrincipals tests

    /**
     * SHIRO-380
     */
    @Test
    void testMergePrincipalsWithDelegatingSubject() {

        def sessionId = "sessionId"

        def principals = createStrictMock(PrincipalCollection)
        def runAsPrincipals = createStrictMock(PrincipalCollection)
        def session = createStrictMock(Session)
        def securityManager = createStrictMock(SecurityManager)

        expect(session.getId()).andStubReturn sessionId
        expect(session.getAttribute(eq(DelegatingSubject.RUN_AS_PRINCIPALS_SESSION_KEY))).andReturn(Arrays.asList(runAsPrincipals))
        expect(principals.isEmpty()).andStubReturn false
        expect(session.getAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY))).andReturn null
        session.setAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY), same(principals));

        replay principals, runAsPrincipals, session, securityManager

        def subject = new DelegatingSubject(principals, true, "localhost", session, true, securityManager)
        new DefaultSubjectDAO().mergePrincipals(subject)

        verify principals, runAsPrincipals, session, securityManager
    }

    /**
     * Tests the case when the Subject has principals but no session yet.  In this case, a session will be created
     * and the session will be set with the principals.
     */
    @Test
    void testMergePrincipalsWithSubjectPrincipalsButWithoutSession() {
        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)
        def principals = createStrictMock(PrincipalCollection)

        expect(subject.runAs).andReturn false
        expect(subject.principals).andReturn principals
        expect(subject.getSession(false)).andReturn null //no session
        expect(principals.isEmpty()).andReturn(false).anyTimes()
        expect(subject.getSession()).andReturn session //new session created
        session.setAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY), same(principals))

        replay subject, session, principals

        dao.mergePrincipals(subject)

        verify subject, session, principals
    }

    /**
     * Tests the case when the Subject has a Session but the subject does not yet have any associated
     * principals and neither does the session.  In this case, the session will be accessed
     * but never updated.
     */
    @Test
    void testMergePrincipalsWithoutSubjectPrincipalsOrSessionPrincipals() {

        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)

        expect(subject.runAs).andReturn false
        expect(subject.principals).andReturn null
        expect(subject.getSession(false)).andReturn(session).anyTimes()

        expect(session.getAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY))).andReturn null

        replay subject, session

        dao.mergePrincipals(subject)

        verify subject, session
    }

    /**
     * Tests the case when the Subject has a Session but the subject does not yet have any associated
     * principals but the session does.  In this case, the session will be accessed and the session-principals will
     * be removed (to match the Subject's state).
     */
    @Test
    void testMergePrincipalsWithoutSubjectPrincipalsButWithSessionPrincipals() {

        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)
        def sessionPrincipals = createStrictMock(PrincipalCollection)

        expect(subject.runAs).andReturn false
        expect(subject.principals).andReturn null
        expect(subject.getSession(false)).andReturn(session).anyTimes()

        expect(session.getAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY))).andReturn sessionPrincipals
        expect(sessionPrincipals.isEmpty()).andReturn false
        expect(session.removeAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY))).andReturn sessionPrincipals

        replay subject, session, sessionPrincipals

        dao.mergePrincipals(subject)

        verify subject, session, sessionPrincipals
    }

    /**
     * Tests the case when the Subject has a Session and the Subject has associated principals, but the session does not
     * yet reflect those principals.  In this case, the session will be accessed and the session will be set with the
     * Subject's principals.
     */
    /*void testMergePrincipalsWithSubjectPrincipalsButWithoutSessionPrincipals() {
        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)
        def subjectPrincipals = createStrictMock(PrincipalCollection)

        expect(subject.principals).andReturn subjectPrincipals
        expect(subject.getSession(false)).andReturn session
        expect(subjectPrincipals.isEmpty()).andReturn false

        expect(session.getAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY))).andReturn null
        session.setAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY), same(subjectPrincipals))

        replay subject, session, subjectPrincipals

        dao.mergePrincipals(subject)

        verify subject, session, subjectPrincipals
    }*/

    /**
     * Tests the case when the Subject has a Session and the Subject has associated principals, but the session reflects
     * different principals.  In this case, the session will be accessed and the session will be set with the
     * Subject's principals.
     */
    @Test
    void testMergePrincipalsWithSubjectPrincipalsButWithDifferentSessionPrincipals() {
        def sessionPrincipals = createStrictMock(PrincipalCollection)

        replay sessionPrincipals

        testMergePrincipalsWithSubjectPrincipalsButWithSessionPrincipals(sessionPrincipals)

        verify sessionPrincipals
    }

    /**
     * Tests the case when the Subject has a Session and the Subject has associated principals, but the session does not
     * yet reflect those principals.  In this case, the session will be accessed and the session will be set with the
     * Subject's principals.
     */
    private void testMergePrincipalsWithSubjectPrincipalsButWithSessionPrincipals(PrincipalCollection sessionPrincipals) {

        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)
        def subjectPrincipals = createStrictMock(PrincipalCollection)

        expect(subject.runAs).andReturn false
        expect(subject.principals).andReturn subjectPrincipals
        expect(subject.getSession(false)).andReturn session
        expect(subjectPrincipals.isEmpty()).andReturn false

        expect(session.getAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY))).andReturn sessionPrincipals
        session.setAttribute(eq(DefaultSubjectContext.PRINCIPALS_SESSION_KEY), same(subjectPrincipals))

        replay subject, session, subjectPrincipals

        dao.mergePrincipals(subject)

        verify subject, session, subjectPrincipals
    }

    // BEGIN: mergeAuthenticationState tests

    /**
     * Tests the case when the Subject is authenticated but doesn't yet have a session.  In this case, a
     * session will be created and the session will be set with the authentication state.
     */
    @Test
    void testMergeAuthcWithSubjectAuthcButWithoutSession() {
        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)

        expect(subject.getSession(false)).andReturn null //no session
        expect(subject.authenticated).andReturn true
        expect(subject.getSession()).andReturn session //new session created
        session.setAttribute(eq(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY), eq(Boolean.TRUE))

        replay subject, session

        dao.mergeAuthenticationState(subject)

        verify subject, session
    }

    /**
     * Tests the case when the Subject has a Session but the subject is not yet authenticated
     * and the session doesn't have an attribute reflecting this.  In this case, the session will be accessed
     * but never updated.
     */
    @Test
    void testMergeAuthcWithoutSubjectAuthcOrSessionAuthc() {

        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)

        expect(subject.getSession(false)).andReturn(session).anyTimes()
        expect(subject.authenticated).andReturn false

        expect(session.getAttribute(eq(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY))).andReturn null

        replay subject, session

        dao.mergeAuthenticationState(subject)

        verify subject, session
    }

    /**
     * Tests the case when the Subject has a Session but the subject is not yet authenticated but the session
     * has authentication state.  In this case, the session will be accessed and the session authc state will
     * be removed to match the Subject's state.
     */
    @Test
    void testMergeAuthcWithoutSubjectAuthcButWithSessionAuthc() {

        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)

        expect(subject.getSession(false)).andReturn(session).anyTimes()
        expect(subject.authenticated).andReturn false

        expect(session.getAttribute(eq(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY))).andReturn Boolean.TRUE
        expect(session.removeAttribute(eq(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY))).andReturn Boolean.TRUE

        replay subject, session

        dao.mergeAuthenticationState(subject)

        verify subject, session
    }

    /**
     * Tests the case when the Subject has a Session and the Subject is authenticated, but the session does not
     * yet reflect that authentication state.  In this case, the session will be accessed and the session will be set
     * with the Subject's authentication state.
     */
    @Test
    void testMergeAuthcWithSubjectAuthcButWithoutSessionAuthc() {
        testMergeAuthcWithSubjectAuthcButWithSessionAuthc(null)
    }

    /**
     * Tests the case when the Subject has a Session and the Subject is authenticated, but the session reflects a
     * different state.  In this case, the session will be accessed and the session will be set with the
     * Subject's authentication state.
     */
    @Test
    void testMergeAuthcWithSubjectAuthcButWithDifferentSessionAuthc() {
        testMergeAuthcWithSubjectAuthcButWithSessionAuthc(Boolean.FALSE)
    }

    /**
     * Tests the case when the Subject has a Session and the Subject has associated principals, but the session does not
     * yet reflect those principals.  In this case, the session will be accessed and the session will be set with the
     * Subject's principals.
     */
    private void testMergeAuthcWithSubjectAuthcButWithSessionAuthc(Boolean value) {

        def dao = new DefaultSubjectDAO()
        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)

        expect(subject.getSession(false)).andReturn session
        expect(subject.authenticated).andReturn true

        expect(session.getAttribute(eq(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY))).andReturn value
        session.setAttribute(eq(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY), eq(Boolean.TRUE))

        replay subject, session

        dao.mergeAuthenticationState(subject)

        verify subject, session
    }

}
