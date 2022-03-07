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

import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.ProvisionException;
import com.google.inject.spi.Dependency;
import com.google.inject.spi.InjectionPoint;
import com.google.inject.spi.ProviderWithDependencies;

class AbstractInjectionProvider<T> implements ProviderWithDependencies<T> {
    private Key<T> key;

    @Inject
    Injector injector;

    private InjectionPoint constructorInjectionPoint;
    private Set<Dependency<?>> dependencies;

    public AbstractInjectionProvider(Key<T> key) {
        this.key = key;
        constructorInjectionPoint = InjectionPoint.forConstructorOf(key.getTypeLiteral());

        Set<Dependency<?>> dependencyBuilder = new HashSet<Dependency<?>>();
        dependencyBuilder.addAll(constructorInjectionPoint.getDependencies());
        for (InjectionPoint injectionPoint : InjectionPoint.forInstanceMethodsAndFields(key.getTypeLiteral())) {
            dependencyBuilder.addAll(injectionPoint.getDependencies());
        }
        this.dependencies = Collections.unmodifiableSet(dependencyBuilder);
    }

    public T get() {
        Constructor<T> constructor = getConstructor();
        Object[] params = new Object[constructor.getParameterTypes().length];
        for (Dependency<?> dependency : constructorInjectionPoint.getDependencies()) {
            params[dependency.getParameterIndex()] = injector.getInstance(dependency.getKey());
        }
        T t;
        try {
            t = constructor.newInstance(params);
        } catch (Exception e) {
            throw new ProvisionException("Could not instantiate " + key + "", e);
        }
        injector.injectMembers(t);
        return postProcess(t);
    }

    @SuppressWarnings({"unchecked"})
    private Constructor<T> getConstructor() {
        return (Constructor<T>) constructorInjectionPoint.getMember();
    }

    protected T postProcess(T t) {
        // do nothing by default
        return t;
    }

    public Set<Dependency<?>> getDependencies() {
        return dependencies;
    }
}
