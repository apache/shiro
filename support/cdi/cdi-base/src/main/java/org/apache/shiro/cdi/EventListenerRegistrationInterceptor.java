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
package org.apache.shiro.cdi;

import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.event.support.DefaultEventBus;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.interceptor.Interceptor;
import javax.interceptor.InterceptorBinding;
import javax.interceptor.InvocationContext;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@EventListenerRegistrationInterceptor.ProcessShiroEventBusConsumer
@Interceptor
@Priority(Interceptor.Priority.LIBRARY_BEFORE + 10)
class EventListenerRegistrationInterceptor {

    private final EventBus eventBus;

    @Inject
    public EventListenerRegistrationInterceptor(EventBus eventBus) {
        this.eventBus = eventBus;
    }

    @PostConstruct
    public Object invoke(final InvocationContext invocationContext) throws Throwable {

        Object target = invocationContext.getTarget();

        // If an object is EventBusAware, do NOT register events directly, just call setEventBus()
        if(target instanceof EventBusAware) {
            ((EventBusAware) target).setEventBus(eventBus);
        }
        else {
            eventBus.register(target);
        }

        return invocationContext.proceed();
    }

    /**
     * A marker annotation, used to assign Shiro annotations problematically.
     */
    @InterceptorBinding
    @Target({ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @interface ProcessShiroEventBusConsumer {}
}
