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

/**
 * A <tt>MethodInterceptor</tt> intercepts a <tt>MethodInvocation</tt> to perform before or after logic (aka 'advice').
 *
 * <p>Shiro's implementations of this interface mostly have to deal with ensuring a current Subject has the
 * ability to execute the method before allowing it to continue.
 *
 * @since 0.2
 */
public interface MethodInterceptor {

    /**
     * Invokes the specified <code>MethodInvocation</code>, allowing implementations to perform pre/post/finally
     * surrounding the actual invocation.
     *
     * @param methodInvocation the <code>MethodInvocation</code> to execute.
     * @return the result of the invocation
     * @throws Throwable if the method invocation throws a Throwable or if an error occurs in pre/post/finally advice.
     */
    Object invoke(MethodInvocation methodInvocation) throws Throwable;

}
