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
package org.apache.shiro.util;

/**
 * A {@code ThreadState} instance manages any state that might need to be bound and/or restored during a thread's
 * execution.
 * <h3>Usage</h3>
 * Calling {@link #bind bind()} will place state on the currently executing thread to be accessed later during
 * the thread's execution.
 * <h4>WARNING</h4>
 * After the thread is finished executing, or if an exception occurs, any previous state <b>MUST</b> be
 * {@link #restore restored} to guarantee all threads stay clean in any thread-pooled environment.  This should always
 * be done in a {@code try/finally} block:
 * <pre>
 * ThreadState state = //acquire or instantiate as necessary
 * try {
 *     state.bind();
 *     doSomething(); //execute any logic downstream logic that might need to access the state
 * } <b>finally {
 *     state.restore();
 * }</b>
 * </pre>
 *
 * @since 1.0
 */
public interface ThreadState {

    /**
     * Binds any state that should be made accessible during a thread's execution.  This should typically always
     * be called in a {@code try/finally} block paired with the {@link #restore} call to guarantee that the thread
     * is cleanly restored back to its original state.  For example:
     * <pre>
     * ThreadState state = //acquire or instantiate as necessary
     * <b>try {
     *     state.bind();
     *     doSomething(); //execute any logic downstream logic that might need to access the state
     * } </b> finally {
     *     state.restore();
     * }
     * </pre>
     */
    void bind();

    /**
     * Restores a thread to its state before bind {@link #bind bind} was invoked.  This should typically always be
     * called in a {@code finally} block to guarantee that the thread is cleanly restored back to its original state
     * before {@link #bind bind}'s bind was called.  For example:
     * <pre>
     * ThreadState state = //acquire or instantiate as necessary
     * try {
     *     state.bind();
     *     doSomething(); //execute any logic downstream logic that might need to access the state
     * } <b>finally {
     *     state.restore();
     * }</b>
     * </pre>
     */
    void restore();

    /**
     * Completely clears/removes the {@code ThreadContext} state.  Typically this method should
     * only be called in special cases - it is more 'correct' to {@link #restore restore} a thread to its previous
     * state than to clear it entirely.
     */
    void clear();

}
