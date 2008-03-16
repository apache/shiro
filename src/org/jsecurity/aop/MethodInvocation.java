/*
 * Copyright 2005-2008 Jeremy Haile, Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.aop;

import java.lang.reflect.Method;

/**
 * 3rd-party API independent representation of a method invocation.  This is needed so JSecurity can support other
 * MethodInvocation instances from other AOP frameworks/APIs.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface MethodInvocation {

    /**
     * Continues the method invocation chain, or if the last in the chain, the method itself.
     * @return the result of the Method invocation.
     * @throws Throwable if the method or chain throws a Throwable
     */
    Object proceed() throws Throwable;

    /**
     * The method that is being invoked.
     * @return a {@link Method} object representing the invoked method.
     */
    Method getMethod();

    /**
     * The arguments given to the method invocation.
     * @return the arguments passed to the method invocation.
     */
    Object[] getArguments();



}

