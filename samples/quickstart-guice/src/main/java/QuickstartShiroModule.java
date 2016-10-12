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
import com.google.inject.Key;
import com.google.inject.Provider;
import com.google.inject.Provides;
import com.google.inject.TypeLiteral;
import com.google.inject.matcher.Matchers;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.name.Names;
import com.google.inject.spi.InjectionListener;
import com.google.inject.spi.TypeEncounter;
import com.google.inject.spi.TypeListener;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.event.LoggingBeanEventListener;
import org.apache.shiro.event.Event;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.Subscribe;
import org.apache.shiro.event.support.AnnotationEventListenerResolver;
import org.apache.shiro.event.support.DefaultEventBus;
import org.apache.shiro.guice.ShiroModule;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.util.ClassUtils;

import javax.inject.Named;
import javax.inject.Singleton;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;

public class QuickstartShiroModule extends ShiroModule {

    private EventBus eventBus;

    @Provides
    @Singleton
    public EventBus getEventBus(@Named("eventListeners") Set<Object> eventListeners) {
        // ignore the eventListeners, we just want to force the initial loading of these.
        if (eventBus == null) {
            eventBus = new DefaultEventBus();
        }
        return eventBus;
    }

    @Provides
    Ini loadShiroIni() {
        return Ini.fromResourcePath("classpath:shiro.ini");
    }

    protected void configureShiro() {

        bindConstant().annotatedWith(Names.named("shiro.securityManager.eventBus")).to(EventBus.class);
        expose(EventBus.class);

        configureEventListeners(Multibinder.newSetBinder(binder(), Object.class, Names.named("eventListeners")));


        bind(Key.get(LoggingBeanEventListener.class));

        bindListener(Matchers.any(), new SubscribedEventTypeListener() );

        try {
            bindRealm().toConstructor(IniRealm.class.getConstructor(Ini.class));
        } catch (NoSuchMethodException e) {
            addError(e);
        }
    }

    protected void configureEventListeners(Multibinder<Object> eventListenerMultibinder ) {

        eventListenerMultibinder.addBinding().to(Key.get(LoggingBeanEventListener.class));
    }


    private class SubscribedEventTypeListener implements TypeListener {

            @Override
            public <I> void hear(TypeLiteral<I> typeLiteral, TypeEncounter<I> typeEncounter) {

            final Provider<EventBus> eventBusProvider = typeEncounter.getProvider(EventBus.class);

            List<Method> methods = ClassUtils.getAnnotatedMethods(typeLiteral.getRawType(), Subscribe.class);
            if (methods != null && !methods.isEmpty()) {
                typeEncounter.register( new InjectionListener<I>() {
                    @Override
                    public void afterInjection(Object o) {
                        eventBusProvider.get().register(o);
                    }
                });
            }
        }
    }

}
