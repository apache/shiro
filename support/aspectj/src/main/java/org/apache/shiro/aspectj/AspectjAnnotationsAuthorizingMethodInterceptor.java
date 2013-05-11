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
package org.apache.shiro.aspectj;

import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.aop.AnnotationsAuthorizingMethodInterceptor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * Extends the annotations authorizing method interceptor class hierarchie to adapt
 * an aspectj {@link JoinPoint} into a {@link MethodInvocation} amd to perform the
 * authorization of method invocations.
 *
 * @since 1.0
 */
public class AspectjAnnotationsAuthorizingMethodInterceptor extends AnnotationsAuthorizingMethodInterceptor {
    /**
     * This class's private log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(AspectjAnnotationsAuthorizingMethodInterceptor.class);

    /**
     * Performs the method interception of the before advice at the specified joint point.
     *
     * @param aJoinPoint The joint point to intercept.
     * @throws Throwable If an error occurs berforming the method invocation.
     */
    protected void performBeforeInterception(JoinPoint aJoinPoint) throws Throwable {
        if (log.isTraceEnabled()) log.trace("#### Invoking a method decorated with a Shiro annotation" +
                "\n\tkind       : " + aJoinPoint.getKind() +
                "\n\tjoinPoint  : " + aJoinPoint +
                "\n\tannotations: " + Arrays.toString(((MethodSignature) aJoinPoint.getSignature()).getMethod().getAnnotations()) +
                "\n\ttarget     : " + aJoinPoint.getTarget()
        );

        // 1. Adapt the join point into a method invocation
        BeforeAdviceMethodInvocationAdapter mi = BeforeAdviceMethodInvocationAdapter.createFrom(aJoinPoint);

        // 2. Delegate the authorization of the method call to the super class
        super.invoke(mi);
    }
}
