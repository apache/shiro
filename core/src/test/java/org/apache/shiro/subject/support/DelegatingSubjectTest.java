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
package org.apache.shiro.subject.support;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SimpleSession;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class DelegatingSubjectTest {

    @Test
    void subject_decorated_only_once() throws IllegalAccessException, NoSuchFieldException {
        // given
        PrincipalCollection principals = new SimplePrincipalCollection("Max Mustermann", "realm");
        boolean authenticated = true;
        String host = "shiro.apache.org.invalid";
        Session innereSession = new SimpleSession(host);
        SecurityManager securityManager = mock(SecurityManager.class);

        // when
        DelegatingSubject delegatingSubject = new DelegatingSubject(
                principals,
                authenticated,
                host,
                innereSession,
                securityManager
        );
        DelegatingSubject twiceDelegatedSubject = new DelegatingSubject(
                principals,
                authenticated,
                host,
                delegatingSubject.getSession(),
                securityManager
        );

        // then
        assertThat(twiceDelegatedSubject.getSession().getClass().getSimpleName()).isEqualTo("StoppingAwareProxiedSession");
        // no new layer added
        assertThat(twiceDelegatedSubject.getSession()).isSameAs(delegatingSubject.getSession());
    }

    @Test
    void session_is_wrapped() {
        // given
        PrincipalCollection principals = new SimplePrincipalCollection("Max Mustermann", "realm");
        boolean authenticated = true;
        String host = "shiro.apache.org.invalid";
        Session innereSession = new SimpleSession(host);
        SecurityManager securityManager = mock(SecurityManager.class);

        // when
        DelegatingSubject delegatingSubject = new DelegatingSubject(
                principals,
                authenticated,
                host,
                innereSession,
                securityManager
        );

        //  then
        assertThat(delegatingSubject.getSession().getClass().getSimpleName()).isEqualTo("StoppingAwareProxiedSession");
    }
}
