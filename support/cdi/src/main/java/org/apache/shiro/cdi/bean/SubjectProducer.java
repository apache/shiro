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

import org.apache.shiro.cdi.loader.Load;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

@ApplicationScoped
public class SubjectProducer {
    private final Class<?>[] interfaces = {Load.load("org.apache.shiro.web.subject.WebSubject", Subject.class)};

    @Produces
    // @RequestScoped but why using this which is actually rarely bound so doing a custom impl
    public Subject subject(final SecurityManager manager) {
        return Subject.class.cast(Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                interfaces,
                new InvocationHandler() {
                    @Override
                    public Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
                        try {
                            final Subject subject = ThreadContext.getSubject();
                            return method.invoke(subject, args);
                        } catch (final InvocationTargetException ite) {
                            throw ite.getCause();
                        }
                    }
                }));
    }
}
