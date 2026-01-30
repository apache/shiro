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

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectCallable;
import org.apache.shiro.subject.support.SubjectRunnable;
import java.util.concurrent.Callable;

public final class ScopedValues {
    private static final ScopedValue<Values> VALUES = ScopedValue.newInstance();

    public static final boolean SCOPED_VALUES_SUPPORTED = true;
    public record Values(SecurityManager securityManager, Subject subject) { }

    private ScopedValues() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static boolean isBound() {
        return VALUES.isBound();
    }

    public static Values get() {
        return VALUES.get();
    }

    public static <T> T call(SubjectCallable<T> callable, Callable<T> target,
                             Subject subject, SecurityManager securityManager) throws Exception {
        return ScopedValue.where(ScopedValues.VALUES, new Values(securityManager, subject))
                .call(() -> callable.doCall(target));
    }

    public static void run(SubjectRunnable runnable, Runnable target, Subject subject, SecurityManager securityManager) {
        ScopedValue.where(ScopedValues.VALUES, new Values(securityManager, subject))
                .run(() -> runnable.doRun(target));
    }
}
