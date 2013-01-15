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
package org.apache.shiro.guice;

import com.google.inject.Key;
import com.google.inject.OutOfScopeException;
import com.google.inject.Provider;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.Test;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertSame;

public class ShiroSessionScopeTest {
    @Test
    public void testScope() throws Exception {
        Subject subject = createMock(Subject.class);
        try {
            final Key<SomeClass> key = Key.get(SomeClass.class);
            Provider<SomeClass> mockProvider = createMock(Provider.class);
            Session session = createMock(Session.class);

            SomeClass retuned = new SomeClass();

            expect(subject.getPrincipal()).andReturn("testUser").anyTimes();

            expect(subject.getSession()).andReturn(session);
            expect(session.getAttribute(key)).andReturn(null);
            expect(mockProvider.get()).andReturn(retuned);

            expect(subject.getSession()).andReturn(session);
            expect(session.getAttribute(key)).andReturn(retuned);


            replay(subject, mockProvider, session);

            ThreadContext.bind(subject);

            ShiroSessionScope underTest = new ShiroSessionScope();

            // first time the session doesn't contain it, we expect the provider to be invoked
            assertSame(retuned, underTest.scope(key, mockProvider).get());
            // second time the session does contain it, we expect the provider to not be invoked
            assertSame(retuned, underTest.scope(key, mockProvider).get());

            verify(subject, mockProvider, session);
        } finally {
            ThreadContext.unbindSubject();
        }

    }

    @Test(expected = OutOfScopeException.class)
    public void testOutOfScope() throws Exception {
        ShiroSessionScope underTest = new ShiroSessionScope();

        Provider<SomeClass> mockProvider = createMock(Provider.class);

        replay(mockProvider);

        underTest.scope(Key.get(SomeClass.class), mockProvider).get();
    }


    static class SomeClass {

    }
}
