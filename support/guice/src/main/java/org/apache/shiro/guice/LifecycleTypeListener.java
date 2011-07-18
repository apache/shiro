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
import com.google.inject.matcher.Matcher;
import com.google.inject.spi.InjectionListener;
import com.google.inject.spi.TypeEncounter;
import com.google.inject.spi.TypeListener;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;


class LifecycleTypeListener implements TypeListener {
    public static final Matcher<TypeLiteral> MATCHER = InitializableInjectionListener.MATCHER.or(DestroyableInjectionListener.MATCHER);
    private DestroyableInjectionListener.DestroyableRegistry registry;

    public LifecycleTypeListener(DestroyableInjectionListener.DestroyableRegistry registry) {
        this.registry = registry;
    }

    public <I> void hear(TypeLiteral<I> type, TypeEncounter<I> encounter) {
        if (InitializableInjectionListener.MATCHER.matches(type)) {
            encounter.register(this.<I>castListener(new InitializableInjectionListener<Initializable>()));
        }
        if (DestroyableInjectionListener.MATCHER.matches(type)) {
            encounter.register(this.<I>castListener(new DestroyableInjectionListener<Destroyable>(registry)));
        }
    }

    @SuppressWarnings({"unchecked"})
    private <I> InjectionListener<? super I> castListener(InjectionListener<?> listener) {
        return (InjectionListener<? super I>) listener;
    }
}
