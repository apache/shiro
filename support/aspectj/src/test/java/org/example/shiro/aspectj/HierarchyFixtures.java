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
package org.example.shiro.aspectj;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;

/**
 * Classes whose Shiro annotations an AspectJ pointcut cannot see directly.
 */
final class HierarchyFixtures {

    private HierarchyFixtures() {
    }

    @RequiresRoles("admin")
    @Target({ElementType.TYPE, ElementType.METHOD})
    @Retention(RetentionPolicy.RUNTIME)
    @interface AdminOnly {
    }

    interface SecuredMethodInterface {
        @RequiresPermissions("dummy:admin")
        void run();
    }

    static class ImplementsSecuredMethod implements SecuredMethodInterface {
        @Override
        public void run() {
        }
    }

    static class SecuredMethodBase {
        @RequiresPermissions("dummy:admin")
        public void run() {
        }
    }

    static class OverridesSecuredMethod extends SecuredMethodBase {
        @Override
        public void run() {
        }
    }

    @RequiresRoles("admin")
    static class SecuredBase {
    }

    static class AddsMethodToSecuredBase extends SecuredBase {
        public void run() {
        }
    }

    static class ComposedOnMethod {
        @AdminOnly
        public void run() {
        }
    }

    @AdminOnly
    static class ComposedOnType {
        public void run() {
        }

        public static void runStatic() {
        }
    }
}
