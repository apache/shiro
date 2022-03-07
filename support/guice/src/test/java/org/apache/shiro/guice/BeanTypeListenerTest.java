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

import com.google.inject.ConfigurationException;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.MembersInjector;
import com.google.inject.Provider;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.google.inject.spi.Message;
import com.google.inject.spi.TypeEncounter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.aop.DefaultAnnotationResolver;
import org.apache.shiro.crypto.cipher.BlowfishCipherService;
import org.apache.shiro.guice.aop.ShiroAopModule;
import org.apache.shiro.guice.web.ShiroWebModule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test Cases::
 * Test package matching
 * injects on classes in shiro package and sub packages
 * excludes classes in shiro-guice package and sub packages
 * Test that properties are set properly
 * ensure optional
 * ensure property names are correct
 * ensure "named" properties require a name, and unnamed do not
 */
public class BeanTypeListenerTest {
    @Test
    public void testUnmatchedPackage() throws Exception {
        assertFalse(BeanTypeListener.MATCHER.matches(TypeLiteral.get(GuiceEnvironment.class)));
        assertFalse(BeanTypeListener.MATCHER.matches(TypeLiteral.get(ShiroWebModule.class)));
        assertFalse(BeanTypeListener.MATCHER.matches(TypeLiteral.get(ShiroAopModule.class)));
    }

    @Test
    public void testMatchedPackage() throws Exception {
        assertTrue(BeanTypeListener.MATCHER.matches(TypeLiteral.get(SecurityUtils.class)));
        assertTrue(BeanTypeListener.MATCHER.matches(TypeLiteral.get(DefaultAnnotationResolver.class)));
        assertTrue(BeanTypeListener.MATCHER.matches(TypeLiteral.get(BlowfishCipherService.class)));
    }

    @Test
    public void testPropertySetting() throws Exception {
        TypeEncounter<SomeInjectableBean> encounter = mock(TypeEncounter.class);

        Provider<Injector> injectorProvider = mock(Provider.class);
        Injector injector = mock(Injector.class);

        when(encounter.getProvider(Injector.class)).then(args -> injectorProvider);

        when(injectorProvider.get()).then(args -> injector);

        ArgumentCaptor<MembersInjector<SomeInjectableBean>> captor = ArgumentCaptor.forClass(MembersInjector.class);

        SecurityManager securityManager = mock(SecurityManager.class);
        String property = "myPropertyValue";

        when(injector.getInstance(Key.get(SecurityManager.class))).then(args -> securityManager);
        when(injector.getInstance(Key.get(String.class, Names.named("shiro.myProperty")))).then(args -> property);
        when(injector.getInstance(Key.get(String.class, Names.named("shiro.unavailableProperty"))))
                .thenThrow(new ConfigurationException(Collections.singleton(new Message("Not Available!"))));
        when((Map) injector.getInstance(BeanTypeListener.MAP_KEY)).then(args -> Collections.EMPTY_MAP);

        BeanTypeListener underTest = new BeanTypeListener();

        underTest.hear(TypeLiteral.get(SomeInjectableBean.class), encounter);

        SomeInjectableBean bean = new SomeInjectableBean();

        verify(encounter).register(captor.capture());
        captor.getValue().injectMembers(bean);

        assertSame(securityManager, bean.securityManager);
        assertSame(property, bean.myProperty);
        assertNull(bean.unavailableProperty);
    }

    public static class SomeInjectableBean {
        private SecurityManager securityManager;
        private String myProperty;
        private String unavailableProperty;

        public void setSecurityManager(SecurityManager securityManager) {

            this.securityManager = securityManager;
        }

        public void setMyProperty(String myProperty) {

            this.myProperty = myProperty;
        }

        public void setUnavailableProperty(String unavailableProperty) {

            this.unavailableProperty = unavailableProperty;
        }
    }
}
