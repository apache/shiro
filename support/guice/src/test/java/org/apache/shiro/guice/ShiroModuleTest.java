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

import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Provides;
import com.google.inject.binder.AnnotatedBindingBuilder;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Destroyable;
import org.junit.Test;

import java.util.Collection;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ShiroModuleTest {

    @Test
    public void basicInstantiation() {

        final MockRealm mockRealm = createMock(MockRealm.class);

        Injector injector = Guice.createInjector(new ShiroModule() {
            @Override
            protected void configureShiro() {
                bindRealm().to(MockRealm.class);
            }

            @Provides
            public MockRealm createRealm() {
                return mockRealm;
            }
        });
        SecurityManager securityManager = injector.getInstance(SecurityManager.class);
        assertNotNull(securityManager);
    }

    @Test
    public void testConfigure() {
        final MockRealm mockRealm = createMock(MockRealm.class);
        AuthenticationToken authToken = createMock(AuthenticationToken.class);
        AuthenticationInfo info = new SimpleAuthenticationInfo("mockUser", "password", "mockRealm");

        expect(mockRealm.supports(authToken)).andReturn(true);
        expect(mockRealm.getAuthenticationInfo(authToken)).andReturn(info);

        replay(mockRealm);

        Injector injector = Guice.createInjector(new ShiroModule() {
            @Override
            protected void configureShiro() {
                bindRealm().to(MockRealm.class);
            }

            @Provides
            public MockRealm createRealm() {
                return mockRealm;
            }
        });
        SecurityManager securityManager = injector.getInstance(SecurityManager.class);
        assertNotNull(securityManager);
        SecurityUtils.setSecurityManager(securityManager);

        final Subject subject = new Subject.Builder(securityManager).buildSubject();
        securityManager.login(subject, authToken);

        verify(mockRealm);
    }

    @Test
    public void testBindSecurityManager() {
        final MockRealm mockRealm = createMock(MockRealm.class);

        Injector injector = Guice.createInjector(new ShiroModule() {
            @Override
            protected void configureShiro() {
                bindRealm().to(MockRealm.class);
            }

            @Provides
            public MockRealm createRealm() {
                return mockRealm;
            }

            @Override
            protected void bindSecurityManager(AnnotatedBindingBuilder<? super SecurityManager> bind) {
                bind.to(MyDefaultSecurityManager.class);
            }
        });
        SecurityManager securityManager = injector.getInstance(SecurityManager.class);
        assertNotNull(securityManager);
        assertTrue(securityManager instanceof MyDefaultSecurityManager);
    }

    @Test
    public void testBindSessionManager() {
        final MockRealm mockRealm = createMock(MockRealm.class);

        Injector injector = Guice.createInjector(new ShiroModule() {
            @Override
            protected void configureShiro() {
                bindRealm().to(MockRealm.class);
            }

            @Provides
            public MockRealm createRealm() {
                return mockRealm;
            }

            @Override
            protected void bindSessionManager(AnnotatedBindingBuilder<SessionManager> bind) {
                bind.to(MyDefaultSessionManager.class);
            }
        });
        DefaultSecurityManager securityManager = (DefaultSecurityManager) injector.getInstance(SecurityManager.class);
        assertNotNull(securityManager);
        assertNotNull(securityManager.getSessionManager());
        assertTrue(securityManager.getSessionManager() instanceof MyDefaultSessionManager);
    }

    @Test
    public void testBindEnvironment() {
        final MockRealm mockRealm = createMock(MockRealm.class);

        Injector injector = Guice.createInjector(new ShiroModule() {
            @Override
            protected void configureShiro() {
                bindRealm().to(MockRealm.class);
                expose(Environment.class);
            }

            @Provides
            public MockRealm createRealm() {
                return mockRealm;
            }

            @Override
            protected void bindEnvironment(AnnotatedBindingBuilder<Environment> bind) {
                bind.to(MyEnvironment.class);
            }
        });
        Environment environment = injector.getInstance(Environment.class);
        assertNotNull(environment);
        assertTrue(environment instanceof MyEnvironment);
    }

    @Test
    public void testDestroy() throws Exception {
        final MockRealm mockRealm = createMock(MockRealm.class);
        final MyDestroyable myDestroyable = createMock(MyDestroyable.class);

        myDestroyable.destroy();

        replay(myDestroyable);

        final ShiroModule shiroModule = new ShiroModule() {
            @Override
            protected void configureShiro() {
                bindRealm().to(MockRealm.class);
                bind(MyDestroyable.class).toInstance(myDestroyable);
                expose(MyDestroyable.class);
            }

            @Provides
            public MockRealm createRealm() {
                return mockRealm;
            }

        };
        Injector injector = Guice.createInjector(shiroModule);
        injector.getInstance(MyDestroyable.class);
        shiroModule.destroy();

        verify(myDestroyable);
    }

    public static interface MockRealm extends Realm {

    }

    public static class MyDefaultSecurityManager extends DefaultSecurityManager {
        @Inject
        public MyDefaultSecurityManager(Collection<Realm> realms) {
            super(realms);
        }
    }

    public static class MyDefaultSessionManager extends DefaultSessionManager {
    }

    public static class MyEnvironment extends GuiceEnvironment {
        @Inject
        public MyEnvironment(SecurityManager securityManager) {
            super(securityManager);
        }
    }

    public static interface MyDestroyable extends Destroyable {
    }
}
