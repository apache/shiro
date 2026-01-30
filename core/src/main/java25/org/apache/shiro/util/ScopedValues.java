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
    private static final ScopedValue<SecurityManager> SECURITY_MANAGER = ScopedValue.newInstance();
    private static final ScopedValue<Subject> SUBJECT = ScopedValue.newInstance();

    public static final boolean SCOPED_VALUES_SUPPORTED = true;

    private ScopedValues() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static boolean hasSecurityManager() {
        return SECURITY_MANAGER.isBound();
    }

    public static SecurityManager getSecurityManager() {
        return SECURITY_MANAGER.get();
    }

    public static boolean hasSubject() {
        return SUBJECT.isBound();
    }

    public static Subject getSubject() {
        return SUBJECT.get();
    }

    public static <T> T call(SubjectCallable<T> callable, Callable<T> target,
                             Subject subject, SecurityManager securityManager) throws Exception {
        return ScopedValue.where(ScopedValues.SUBJECT, subject)
                .where(ScopedValues.SECURITY_MANAGER, securityManager)
                .call(() -> callable.doCall(target));
    }

    public static void run(SubjectRunnable runnable, Runnable target, Subject subject, SecurityManager securityManager) {
        ScopedValue.where(ScopedValues.SUBJECT, subject)
                .where(ScopedValues.SECURITY_MANAGER, securityManager)
                .run(() -> runnable.doRun(target));
    }
}
