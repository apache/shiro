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
package org.apache.shiro.aop;

import java.lang.reflect.Method;

/**
 * 3rd-party API independent representation of a method invocation.  This is needed so Shiro can support other
 * MethodInvocation instances from other AOP frameworks/APIs.
 *
 * @since 0.1
 */
public interface MethodInvocation {

    /**
     * Continues the method invocation chain, or if the last in the chain, the method itself.
     *
     * @return the result of the Method invocation.
     * @throws Throwable if the method or chain throws a Throwable
     */
    Object proceed() throws Throwable;

    /**
     * Returns the actual {@link Method Method} to be invoked.
     *
     * @return the actual {@link Method Method} to be invoked.
     */
    Method getMethod();

    /**
     * Returns the (possibly null) arguments to be supplied to the method invocation.
     *
     * @return the (possibly null) arguments to be supplied to the method invocation.
     */
    Object[] getArguments();

    /**
     * Returns the object that holds the current joinpoint's static part.
     * For instance, the target object for an invocation.
     *
     * @return the object that holds the current joinpoint's static part.
     * @since 1.0
     */
    Object getThis();


}

