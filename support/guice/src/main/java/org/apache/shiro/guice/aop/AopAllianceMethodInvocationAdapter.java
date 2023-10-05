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
package org.apache.shiro.guice.aop;

import org.aopalliance.intercept.MethodInvocation;

import java.lang.reflect.Method;

/**
 * Adapts a Shiro {@link org.apache.shiro.aop.MethodInvocation MethodInvocation} to an AOPAlliance
 * {@link org.aopalliance.intercept.MethodInvocation}.
 */
class AopAllianceMethodInvocationAdapter implements org.apache.shiro.aop.MethodInvocation {
    private final MethodInvocation mi;

    AopAllianceMethodInvocationAdapter(MethodInvocation mi) {
        this.mi = mi;
    }

    public Method getMethod() {
        return mi.getMethod();
    }

    public Object[] getArguments() {
        return mi.getArguments();
    }

    public String toString() {
        return "Method invocation [" + mi.getMethod() + "]";
    }

    public Object proceed() throws Throwable {
        return mi.proceed();
    }

    public Object getThis() {
        return mi.getThis();
    }
}
