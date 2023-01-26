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
package org.apache.shiro.cdi.environment;

import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import java.io.Closeable;
import java.util.ArrayList;
import java.util.Collection;

public class CdiLookups implements Closeable {
    private final BeanManager beanManager;
    private final Collection<CreationalContext<?>> contextsToRelease = new ArrayList<CreationalContext<?>>();

    public CdiLookups(final BeanManager beanManager) {
        this.beanManager = beanManager;
    }

    public <T> T getObject(final String name, final Class<T> requiredType) {
        final Bean<?> bean = beanManager.resolve(beanManager.getBeans(name));
        if (bean != null && bean.getTypes().contains(requiredType)) {
            final CreationalContext<?> creationalContext = beanManager.createCreationalContext(null);
            if (!beanManager.isNormalScope(bean.getScope())) {
                synchronized (contextsToRelease) {
                    contextsToRelease.add(creationalContext);
                }
            }
            return requiredType.cast(beanManager.getReference(bean, requiredType, creationalContext));
        }
        return null;
    }

    @Override
    public void close() {
        for (final CreationalContext<?> creationalContext : contextsToRelease) {
            creationalContext.release();
        }
    }
}
