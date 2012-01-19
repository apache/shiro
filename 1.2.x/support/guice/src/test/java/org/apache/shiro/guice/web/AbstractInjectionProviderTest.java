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
package org.apache.shiro.guice.web;

import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.name.Named;
import com.google.inject.name.Names;
import com.google.inject.spi.Dependency;
import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

public class AbstractInjectionProviderTest {

    @Test
    public void testGet() throws Exception {
        Injector mockInjector = createMock(Injector.class);

        Object c1 = new Object();
        Object c2 = new Object();
        final AtomicBoolean postProcessCalled = new AtomicBoolean(false);

        expect(mockInjector.getInstance(keyC1)).andReturn(c1);
        expect(mockInjector.getInstance(keyC2)).andReturn(c2);
        mockInjector.injectMembers(anyObject(SomeInjectedClass.class));

        replay(mockInjector);

        AbstractInjectionProvider<SomeInjectedClass> underTest =
                new AbstractInjectionProvider<SomeInjectedClass>(Key.get(SomeInjectedClass.class)) {
                    @Override
                    protected SomeInjectedClass postProcess(SomeInjectedClass someInjectedClass) {
                        postProcessCalled.set(true);
                        return super.postProcess(someInjectedClass);
                    }
                };

        underTest.injector = mockInjector;

        SomeInjectedClass got = underTest.get();

        assertEquals("Wrong parameter passed to constructor (index 0).", c1, got.c1);
        assertEquals("Wrong parameter passed to constructor (index 1).", c2, got.c2);

        assertTrue("postProcess method was not called.", postProcessCalled.get());

        verify(mockInjector);
    }

    @Test
    public void testGetDependencies() throws Exception {
        AbstractInjectionProvider<SomeInjectedClass> underTest =
                new AbstractInjectionProvider<SomeInjectedClass>(Key.get(SomeInjectedClass.class));

        boolean foundC1 = false;
        boolean foundC2 = false;
        boolean foundV1 = false;
        boolean foundV2 = false;
        boolean foundF1 = false;

        for (Dependency<?> dependency : underTest.getDependencies()) {
            if (dependency.getInjectionPoint().getMember() instanceof Constructor) {
                if (dependency.getParameterIndex() == 0 && dependency.getKey().equals(keyC1)) {
                    foundC1 = true;
                } else if (dependency.getParameterIndex() == 1 && dependency.getKey().equals(keyC2)) {
                    foundC2 = true;
                } else {
                    fail("Did not expect constructor dependency with key " + dependency.getKey() + " at parameter index " + dependency.getParameterIndex());
                }
            } else if (dependency.getInjectionPoint().getMember() instanceof Method) {
                if (dependency.getKey().equals(keyV1)) {
                    foundV1 = true;
                } else if (dependency.getKey().equals(keyV2)) {
                    foundV2 = true;
                } else {
                    fail("Did not expect method dependency with key " + dependency.getKey());
                }
            } else if (dependency.getInjectionPoint().getMember() instanceof Field) {
                if (dependency.getKey().equals(keyF1)) {
                    foundF1 = true;
                } else {
                    fail("Did not expect field dependency with key " + dependency.getKey());
                }
            } else {
                fail("Did not expect dependency with key " + dependency.getKey());
            }
        }

        assertTrue("Did not find dependency C1", foundC1);
        assertTrue("Did not find dependency C2", foundC2);
        assertTrue("Did not find dependency V1", foundV1);
        assertTrue("Did not find dependency V2", foundV2);
        assertTrue("Did not find dependency F1", foundF1);
    }

    static Key keyC1 = Key.get(Object.class, Names.named("constructor1"));
    static Key keyC2 = Key.get(Object.class, Names.named("constructor2"));
    static Key keyV1 = Key.get(Object.class, Names.named("val1"));
    static Key keyV2 = Key.get(Object.class, Names.named("val2"));
    static Key keyF1 = Key.get(Object.class, Names.named("field1"));


    static class SomeInjectedClass {

        @Inject
        @Named("field1")
        private Object field;
        private Object c1;
        private Object c2;

        @Inject
        public SomeInjectedClass(@Named("constructor1") Object c1, @Named("constructor2") Object c2) {

            this.c1 = c1;
            this.c2 = c2;
        }

        @Inject
        public void setVal1(@Named("val1") Object v1) {

        }

        @Inject
        public void setVal2(@Named("val2") Object v2) {

        }
    }
}
