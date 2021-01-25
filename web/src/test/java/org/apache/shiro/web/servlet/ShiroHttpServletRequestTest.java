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
package org.apache.shiro.web.servlet;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ShiroHttpServletRequestTest {

    private ShiroHttpServletRequest request;

    private HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    private ServletContext mockContext = mock(ServletContext.class);
    private Subject mockSubject = mock(Subject.class);

    @BeforeEach
    public void setUp() throws Exception {
        ThreadContext.bind(this.mockSubject);
        this.request = new ShiroHttpServletRequest(mockRequest, mockContext, false);
    }
    
    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-637">SHIRO-637<a/>.
     */
    @Test
    public void testRegetSession() {
        Session session1 = mock(Session.class);
        Session session2 = mock(Session.class);
        AtomicInteger counter = new AtomicInteger();
        AtomicInteger counterFalse = new AtomicInteger();

        mockSubject.logout();
        when(mockSubject.getSession(true)).then(args -> {
            if (counter.getAndIncrement() == 1) {
                return session1;
            }

            return session2;
        });
        when(mockSubject.getSession(false)).then(args -> {
           if (counterFalse.getAndIncrement() < 2) {
               return session1;
           }

           return null;
        });

        assertNotNull(request.getSession(true));
        assertNotNull(request.getSession(false));
        
        mockSubject.logout();
        
        assertNull(request.getSession(false));
        assertNotNull(request.getSession(true));
        verify(mockSubject, times(2)).getSession(true);
        verify(mockSubject, atLeast(3)).getSession(false);
    }
}
