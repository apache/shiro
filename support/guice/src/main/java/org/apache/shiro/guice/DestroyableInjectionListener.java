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
import com.google.inject.matcher.Matchers;
import com.google.inject.spi.InjectionListener;
import org.apache.shiro.util.Destroyable;

/**
 * Injection listener that assists with honoring the {@link org.apache.shiro.util.Destroyable} interface.
 *
 * @param <I>
 */
class DestroyableInjectionListener<I extends Destroyable> implements InjectionListener<I> {
    public static final Matcher<TypeLiteral> MATCHER = ShiroMatchers.typeLiteral(Matchers.subclassesOf(Destroyable.class));

    private DestroyableRegistry registry;

    public DestroyableInjectionListener(DestroyableRegistry registry) {
        this.registry = registry;
    }

    public void afterInjection(Destroyable injectee) {
        registry.add(injectee);
    }

    public static interface DestroyableRegistry {
        void add(Destroyable destroyable);
    }
}
