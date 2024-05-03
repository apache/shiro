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
package org.apache.shiro;

import lombok.RequiredArgsConstructor;
import lombok.experimental.Delegate;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.mgt.WrappedSecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.apache.shiro.SecurityUtils.getSecurityManager;
import static org.apache.shiro.SecurityUtils.isSecurityManagerTypeOf;
import static org.apache.shiro.SecurityUtils.unwrapSecurityManager;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityUtilsUnwrapTest {
    @Mock
    SecurityManager securityManager;
    @Mock
    DefaultSecurityManager defaultSecurityManager;
    @Mock
    Subject subject;
    @Mock
    SubjectContext subjectContext;

    @RequiredArgsConstructor
    static class Wrapped implements WrappedSecurityManager, SecurityManager {
        private final @Delegate SecurityManager securityManager;

        @Override
        @SuppressWarnings("unchecked")
        public <SM extends SecurityManager> SM unwrap() {
            return (SM) securityManager;
        }
    }

    @RequiredArgsConstructor
    static class InvalidWrapped implements WrappedSecurityManager, SecurityManager {
        private final @Delegate SecurityManager securityManager;

        @Override
        @SuppressWarnings("unchecked")
        public <SM extends SecurityManager> SM unwrap() {
            return (SM) this;
        }
    }

    @Test
    void basicUnwrap() {
        SecurityManager sm = unwrapSecurityManager(securityManager, SecurityManager.class);
        assertEquals(securityManager, sm);
    }

    @Test
    void basicTypeCheck() {
        assertTrue(isSecurityManagerTypeOf(securityManager, SecurityManager.class));
    }

    @Test
    void securityManager() {
        try (var threadContext = mockStatic(ThreadContext.class)) {
            threadContext.when(ThreadContext::getSecurityManager).thenReturn(defaultSecurityManager);
            DefaultSecurityManager dsm = getSecurityManager(DefaultSecurityManager.class);
            assertEquals(defaultSecurityManager, dsm);
        }
    }

    @Test
    void failedTypeUnwrap() {
        assertThrows(ClassCastException.class, () -> {
            SessionsSecurityManager ssm = unwrapSecurityManager(securityManager, SessionsSecurityManager.class);
        });
    }

    @Test
    void defaultSecurityManager() {
        var dsm = unwrapSecurityManager(defaultSecurityManager, DefaultSecurityManager.class);
        assertEquals(defaultSecurityManager, dsm);
        when(defaultSecurityManager.createSubject(subjectContext)).thenReturn(subject);
        Subject subject = dsm.createSubject(subjectContext);
        assertEquals(this.subject, subject);
        verify(defaultSecurityManager).createSubject(subjectContext);
        verifyNoMoreInteractions(defaultSecurityManager, this.subject, subjectContext);
    }

    @Test
    void invalidCast() {
        SecurityManager wrapped = new Wrapped(defaultSecurityManager);
        assertThrows(ClassCastException.class, () -> {
            DefaultSecurityManager sm = (DefaultSecurityManager) wrapped;
        });
    }

    @Test
    void unwrapOne() {
        SecurityManager wrapped = new Wrapped(defaultSecurityManager);
        assertEquals(defaultSecurityManager, unwrapSecurityManager(wrapped, DefaultSecurityManager.class));
    }

    @Test
    void unwrapTwo() {
        SecurityManager wrapped = new Wrapped(new Wrapped(defaultSecurityManager));
        assertEquals(defaultSecurityManager, unwrapSecurityManager(wrapped, DefaultSecurityManager.class));
    }

    @Test
    void invalidWrap() {
        SecurityManager wrapped = new Wrapped(new InvalidWrapped(defaultSecurityManager));
        assertThrows(IllegalStateException.class, () -> {
            assertEquals(defaultSecurityManager, unwrapSecurityManager(wrapped, DefaultSecurityManager.class));
        });
    }

    @Test
    void invalidWrapInverted() {
        SecurityManager wrapped = new InvalidWrapped(new Wrapped(defaultSecurityManager));
        assertThrows(IllegalStateException.class, () -> {
            assertEquals(defaultSecurityManager, unwrapSecurityManager(wrapped, DefaultSecurityManager.class));
        });
    }
}
