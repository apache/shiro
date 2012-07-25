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

import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.junit.Test;

import static org.junit.Assert.assertNull;

/**
 * Test cases for the {@link AbstractRememberMeManager} implementation.
 */
public class AbstractRememberMeManagerTest {

    /**
     * Tests the {@link AbstractRememberMeManager#getRememberedPrincipals(SubjectContext)} method
     * implementation when the internal
     * {@link AbstractRememberMeManager#getRememberedSerializedIdentity(SubjectContext)} method
     * returns null or empty bytes.
     */
    @Test
    public void testGetRememberedPrincipalsWithEmptySerializedBytes() {
        AbstractRememberMeManager rmm = new DummyRememberMeManager();
        //Since the dummy's getRememberedSerializedIdentity implementation returns an empty byte
        //array, we should be ok:
        PrincipalCollection principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertNull(principals);

        //try with a null return value too:
        rmm = new DummyRememberMeManager() {
            @Override
            protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
                return null;
            }
        };
        principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertNull(principals);
    }

    private static class DummyRememberMeManager extends AbstractRememberMeManager {
        public void forgetIdentity(SubjectContext subjectContext) {
            //do nothing
        }

        @Override
        protected void forgetIdentity(Subject subject) {
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return new byte[0];
        }
    }
}
