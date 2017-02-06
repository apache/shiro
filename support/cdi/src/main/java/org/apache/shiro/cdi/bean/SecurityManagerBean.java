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
package org.apache.shiro.cdi.bean;

import org.apache.shiro.cdi.literal.AnyLiteral;
import org.apache.shiro.cdi.literal.DefaultLiteral;
import org.apache.shiro.mgt.SecurityManager;

import javax.enterprise.context.Dependent;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.InjectionPoint;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;

public class SecurityManagerBean implements Bean<SecurityManager> {
    private final Set<Type> types = new HashSet<Type>(asList(SecurityManager.class, SecurityManager.class, Object.class));
    private final Set<Annotation> qualifiers = new HashSet<Annotation>(asList(new DefaultLiteral(), new AnyLiteral()));
    private SecurityManager manager;
    private Class<?> type;

    public SecurityManagerBean(final Class<?> type) {
        this.type = type;
    }

    public void initSecurityManagerBean(final SecurityManager manager) {
        this.manager = manager;
    }

    @Override
    public Set<InjectionPoint> getInjectionPoints() {
        return emptySet();
    }

    @Override
    public Class<?> getBeanClass() {
        return type;
    }

    @Override
    public boolean isNullable() {
        return false;
    }

    @Override
    public SecurityManager create(final CreationalContext<SecurityManager> context) {
        return manager;
    }

    @Override
    public void destroy(final SecurityManager instance, final CreationalContext<SecurityManager> context) {
        // no-op
    }

    @Override
    public Set<Type> getTypes() {
        return types;
    }

    @Override
    public Set<Annotation> getQualifiers() {
        return qualifiers;
    }

    @Override // avoid proxies
    public Class<? extends Annotation> getScope() {
        return Dependent.class;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public Set<Class<? extends Annotation>> getStereotypes() {
        return emptySet();
    }

    @Override
    public boolean isAlternative() {
        return false;
    }
}
