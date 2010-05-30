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
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.AdviceSignature;
import org.aspectj.lang.reflect.MethodSignature;

import java.lang.reflect.Method;

/**
 * Helper class that adapts an AspectJ {@link JoinPoint JoinPoint}.
 *
 * @since 1.0
 */
public class BeforeAdviceMethodInvocationAdapter implements MethodInvocation {

    private Object _object;
    private Method _method;
    private Object[] _arguments;

    /**
     * Factory method that creates a new {@link BeforeAdviceMethodInvocationAdapter} instance
     * using the AspectJ {@link JoinPoint} provided. If the joint point passed in is not
     * a method joint point, this method throws an {@link IllegalArgumentException}.
     *
     * @param aJoinPoint The AspectJ {@link JoinPoint} to use to adapt the advice.
     * @return The created instance.
     * @throws IllegalArgumentException If the join point passed in does not involve a method call.
     */
    public static BeforeAdviceMethodInvocationAdapter createFrom(JoinPoint aJoinPoint) {
        if (aJoinPoint.getSignature() instanceof MethodSignature) {
            return new BeforeAdviceMethodInvocationAdapter(aJoinPoint.getThis(),
                    ((MethodSignature) aJoinPoint.getSignature()).getMethod(),
                    aJoinPoint.getArgs());

        } else if (aJoinPoint.getSignature() instanceof AdviceSignature) {
            return new BeforeAdviceMethodInvocationAdapter(aJoinPoint.getThis(),
                    ((AdviceSignature) aJoinPoint.getSignature()).getAdvice(),
                    aJoinPoint.getArgs());

        } else {
            throw new IllegalArgumentException("The joint point signature is invalid: expected a MethodSignature or an AdviceSignature but was " + aJoinPoint.getSignature());
        }
    }

    /**
     * Creates a new {@link BeforeAdviceMethodInvocationAdapter} instance.
     *
     * @param aMethod       The method to invoke.
     * @param someArguments The arguments of the method invocation.
     */
    public BeforeAdviceMethodInvocationAdapter(Object anObject, Method aMethod, Object[] someArguments) {
        _object = anObject;
        _method = aMethod;
        _arguments = someArguments;
    }

    /* (non-Javadoc)
    * @see org.apache.shiro.aop.MethodInvocation#getArguments()
    */

    public Object[] getArguments() {
        return _arguments;
    }

    /* (non-Javadoc)
    * @see org.apache.shiro.aop.MethodInvocation#getMethod()
    */

    public Method getMethod() {
        return _method;
    }

    /* (non-Javadoc)
    * @see org.apache.shiro.aop.MethodInvocation#proceed()
    */

    public Object proceed() throws Throwable {
        // Do nothing since this adapts a before advice
        return null;
    }

    /**
     * @since 1.0
     */
    public Object getThis() {
        return _object;
    }
}
