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

import com.google.common.collect.Sets;
import com.google.inject.Key;
import com.google.inject.PrivateModule;
import com.google.inject.TypeLiteral;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.binder.LinkedBindingBuilder;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.util.Types;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.util.Destroyable;

import javax.annotation.PreDestroy;
import java.util.Collection;
import java.util.Set;
import java.util.WeakHashMap;


/**
 * Sets up Shiro lifecycles within Guice, enables the injecting of Shiro objects, and binds a default
 * {@link org.apache.shiro.mgt.SecurityManager} and {@link org.apache.shiro.session.mgt.SessionManager}.  At least one realm must be added by using
 * {@link #bindRealm() bindRealm}.
 */
public abstract class ShiroModule extends PrivateModule implements Destroyable {

    private Set<Destroyable> destroyables = Sets.newSetFromMap(new WeakHashMap<Destroyable, Boolean>());

    public void configure() {
        // setup security manager
        bindSecurityManager(bind(SecurityManager.class));
        bindSessionManager(bind(SessionManager.class));
        bindEnvironment(bind(Environment.class));
        bindListener(BeanTypeListener.MATCHER, new BeanTypeListener());
        final DestroyableInjectionListener.DestroyableRegistry registry = new DestroyableInjectionListener.DestroyableRegistry() {
            public void add(Destroyable destroyable) {
                ShiroModule.this.add(destroyable);
            }

            @PreDestroy
            public void destroy() throws Exception {
                ShiroModule.this.destroy();
            }
        };
        bindListener(LifecycleTypeListener.MATCHER, new LifecycleTypeListener(registry));

        expose(SecurityManager.class);

        configureShiro();
        bind(realmCollectionKey())
                .to(realmSetKey());

        bind(DestroyableInjectionListener.DestroyableRegistry.class).toInstance(registry);
        BeanTypeListener.ensureBeanTypeMapExists(binder());
    }

    @SuppressWarnings({"unchecked"})
    private Key<Set<Realm>> realmSetKey() {
        return (Key<Set<Realm>>) Key.get(TypeLiteral.get(Types.setOf(Realm.class)));
    }

    @SuppressWarnings({"unchecked"})
    private Key<Collection<Realm>> realmCollectionKey() {
        return (Key<Collection<Realm>>) Key.get(Types.newParameterizedType(Collection.class, Realm.class));
    }

    /**
     * Implement this method in order to configure your realms and any other Shiro customization you may need.
     */
    protected abstract void configureShiro();

    /**
     * This is the preferred manner to bind a realm.  The {@link org.apache.shiro.mgt.SecurityManager} will be injected with any Realm bound
     * with this method.
     *
     * @return a binding builder for a realm
     */
    protected final LinkedBindingBuilder<Realm> bindRealm() {
        Multibinder<Realm> multibinder = Multibinder.newSetBinder(binder(), Realm.class);
        return multibinder.addBinding();
    }

    /**
     * Binds the security manager.  Override this method in order to provide your own security manager binding.
     * <p/>
     * By default, a {@link org.apache.shiro.mgt.DefaultSecurityManager} is bound as an eager singleton.
     *
     * @param bind
     */
    protected void bindSecurityManager(AnnotatedBindingBuilder<? super SecurityManager> bind) {
        try {
            bind.toConstructor(DefaultSecurityManager.class.getConstructor(Collection.class)).asEagerSingleton();
        } catch (NoSuchMethodException e) {
            throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
        }
    }

    /**
     * Binds the session manager.  Override this method in order to provide your own session manager binding.
     * <p/>
     * By default, a {@link org.apache.shiro.session.mgt.DefaultSessionManager} is bound as an eager singleton.
     *
     * @param bind
     */
    protected void bindSessionManager(AnnotatedBindingBuilder<SessionManager> bind) {
        bind.to(DefaultSessionManager.class).asEagerSingleton();
    }

    /**
     * Binds the environment.  Override this method in order to provide your own environment binding.
     * <p/>
     * By default, a {@link GuiceEnvironment} is bound as an eager singleton.
     *
     * @param bind
     */
    protected void bindEnvironment(AnnotatedBindingBuilder<Environment> bind) {
        bind.to(GuiceEnvironment.class).asEagerSingleton();
    }

    /**
     * Binds a key to use for injecting setters in shiro classes.
     * @param typeLiteral the bean property type
     * @param key the key to use to satisfy the bean property dependency
     * @param <T>
     */
    protected final <T> void bindBeanType(TypeLiteral<T> typeLiteral, Key<? extends T> key) {
        BeanTypeListener.bindBeanType(binder(), typeLiteral, key);
    }

    /**
     * Destroys all beans created within this module that implement {@link org.apache.shiro.util.Destroyable}.  Should be called when this
     * module will no longer be used.
     *
     * @throws Exception
     */
    public final void destroy() throws Exception {
        for (Destroyable destroyable : destroyables) {
            destroyable.destroy();
        }
    }

    public void add(Destroyable destroyable) {
        this.destroyables.add(destroyable);
    }
}
