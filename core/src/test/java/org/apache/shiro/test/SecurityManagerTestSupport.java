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
package org.apache.shiro.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.Ini;
import org.apache.shiro.lang.util.LifecycleUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import java.util.Objects;

/**
 * Utility methods for use by Shiro test case subclasses.  You can use these methods as examples for your own
 * test cases, but you SHOULD NOT use any ThreadContext API calls in your actual application code.
 * The utility methods here make heavy assumptions about Shiro's implementation details, and your
 * application code should definitely not.
 * <p/>
 * See the <a href="http://cwiki.apache.org/confluence/display/SHIRO/Subject">wiki Subject documentation</a>
 * for proper application practices using Subject instances with threads.
 */
public class SecurityManagerTestSupport {

    protected static SecurityManager createTestSecurityManager() {
        Ini ini = new Ini();
        ini.setSectionProperty("users", "test", "test");
        return new DefaultSecurityManager(new IniRealm(ini));
    }

    protected void destroy(SecurityManager sm) {
        LifecycleUtils.destroy(sm);
    }

    protected SecurityManager createAndBindTestSecurityManager() {
        SecurityManager sm = createTestSecurityManager();
        ThreadContext.bind(sm);
        return sm;
    }

    protected Subject createAndBindTestSubject() {
        SecurityManager sm = ThreadContext.getSecurityManager();
        if (sm == null) {
            createAndBindTestSecurityManager();
        }
        return SecurityUtils.getSubject();
    }

    protected Subject createSubject() {
        SecurityManager securityManager = createTestSecurityManager();
        return new Subject.Builder(securityManager).buildSubject();
    }

    /**
     * Associates the {@code consumer} with the {@code subject} and executes. If an exception was thrown by the
     * consumer, it is re-thrown by this method.
     *
     * @param subject  The subject to bind to the current thread.
     * @param consumer The block of code to run under the context of the subject.
     * @throws Exception propagates any exception thrown by the consumer.
     */
    protected void runWithSubject(Subject subject, SubjectConsumer consumer) {
        Exception exception = subject.execute(() -> {
            try {
                consumer.accept(subject);
                return null;
            } catch (Exception e) {
                return e;
            }
        });
        if (Objects.nonNull(exception)) {
            throw new RuntimeException("Test execution threw exception", exception);
        }
    }

    protected void runWithSubject(SubjectConsumer consumer) {
        runWithSubject(createSubject(), consumer);
    }

    @FunctionalInterface
    protected interface SubjectConsumer {
        void accept(Subject subject) throws Exception;
    }
}
