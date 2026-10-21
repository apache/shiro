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
package org.apache.shiro.web.filter.authc;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

/**
 * Test for {@link NoAccessFilter}.
 */
public class NoAccessFilterTest {

    @Test
    void authenticatedSubjectIsDenied() {
        Subject subject = createNiceMock(Subject.class);
        expect(subject.isAuthenticated()).andReturn(true).anyTimes();
        expect(subject.getPrincipal()).andReturn("user").anyTimes();
        replay(subject);

        NoAccessFilter filter = new NoAccessFilter() {
            @Override
            protected Subject getSubject(ServletRequest request, ServletResponse response) {
                return subject;
            }
        };

        assertThat(filter.isAccessAllowed(null, null, null)).isFalse();
    }

    @Test
    void anonymousSubjectIsDenied() {
        assertThat(new NoAccessFilter().isAccessAllowed(null, null, null)).isFalse();
    }
}
