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
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.event.Subscribe;
import org.apache.shiro.lang.util.Destroyable;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import java.util.Collection;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Isolated("System property usage")
public class ShiroModuleTest {

    @Test
    void basicInstantiation() {

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
    void testConfigure() {
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
    void testBindSecurityManager() {
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
    void testBindSessionManager() {
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
    void testBindEnvironment() {
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
    void testDestroy() throws Exception {
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

    /**
     * @throws Exception
     * @since 1.4
     */
    @Test
    void testEventListener() throws Exception {

        final MockRealm mockRealm = createMock(MockRealm.class);
        final EventBus eventBus = createMock(EventBus.class);

        // expect both objects to be registered
        eventBus.register(anyObject(MockEventListener1.class));
        eventBus.register(anyObject(MockEventListener2.class));
        replay(eventBus);

        final ShiroModule shiroModule = new ShiroModule() {
            @Override
            protected void configureShiro() {
                bindRealm().to(MockRealm.class);

                // bind our event listeners
                binder().bind(MockEventListener1.class).asEagerSingleton();
                binder().bind(MockEventListener2.class).asEagerSingleton();
            }

            @Override
            protected void bindEventBus(AnnotatedBindingBuilder<EventBus> bind) {
                bind.toInstance(eventBus);
            }

            @Provides
            public MockRealm createRealm() {
                return mockRealm;
            }

        };
        Guice.createInjector(shiroModule);

        verify(eventBus);

    }

    /**
     * @throws Exception
     * @since 1.4
     */
    @Test
    void testEventBusAware() throws Exception {

        final MockRealm mockRealm = createMock(MockRealm.class);

        final ShiroModule shiroModule = new ShiroModule() {
            @Override
            protected void configureShiro() {
                bindRealm().to(MockRealm.class);

                binder().bind(MockEventBusAware.class).asEagerSingleton();
                expose(MockEventBusAware.class);
            }

            @Provides
            public MockRealm createRealm() {
                return mockRealm;
            }

        };
        Injector injector = Guice.createInjector(shiroModule);
        EventBus eventBus = injector.getInstance(EventBus.class);
        SecurityManager securityManager = injector.getInstance(SecurityManager.class);

        MockEventBusAware eventBusAware = injector.getInstance(MockEventBusAware.class);

        assertSame(eventBus, eventBusAware.eventBus);
        assertSame(eventBus, ((DefaultSecurityManager) securityManager).getEventBus());
    }

    public interface MockRealm extends Realm {

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

    public interface MyDestroyable extends Destroyable {
    }

    public static class MockEventListener1 {
        @Subscribe
        public void listenToAllAndDoNothing(Object o) {
        }
    }

    public static class MockEventListener2 {
        @Subscribe
        public void listenToAllAndDoNothing(Object o) {
        }
    }

    public static class MockEventBusAware implements EventBusAware {
        private EventBus eventBus;

        public EventBus getEventBus() {
            return eventBus;
        }

        @Override
        public void setEventBus(EventBus eventBus) {
            this.eventBus = eventBus;
        }
    }
}
