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

import com.google.inject.TypeLiteral;
import com.google.inject.spi.TypeEncounter;
import org.apache.shiro.lang.ShiroException;
import org.apache.shiro.lang.util.Destroyable;
import org.apache.shiro.lang.util.Initializable;
import org.junit.jupiter.api.Test;

import static org.easymock.EasyMock.*;

public class LifecycleTypeListenerTest {
    @Test
    void testHearInitializable() throws Exception {
        TypeEncounter encounter = createMock(TypeEncounter.class);

        encounter.register(anyObject(InitializableInjectionListener.class));

        replay(encounter);

        LifecycleTypeListener underTest = new LifecycleTypeListener(null);

        underTest.hear(TypeLiteral.get(MyInitializable.class), encounter);

        verify(encounter);
    }

    @Test
    void testHearDestroyable() throws Exception {
        TypeEncounter encounter = createMock(TypeEncounter.class);

        encounter.register(anyObject(DestroyableInjectionListener.class));

        replay(encounter);

        LifecycleTypeListener underTest = new LifecycleTypeListener(null);

        underTest.hear(TypeLiteral.get(MyDestroyable.class), encounter);

        verify(encounter);
    }

    static class MyInitializable implements Initializable {

        public void init() throws ShiroException {
            // do nothing
        }
    }

    static class MyDestroyable implements Destroyable {
        public void destroy() throws Exception {
            // do nothing
        }
    }
}
