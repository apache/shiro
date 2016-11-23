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

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

public final class JavaxSecurityRoleStubs {

    public interface SimpleStub {
        boolean callMe();
    }


    @RolesAllowed("RoleOne")
    public static class RolesAllowedOnClass implements SimpleStub {
        public boolean callMe() {
            return true;
        }
    }

    public static class RolesAllowedOnMethod implements SimpleStub {
        @RolesAllowed("RoleOne")
        public boolean callMe() {
            return true;
        }
    }

    public static class PermitAllOnMethod implements SimpleStub {
        @PermitAll
        public boolean callMe() {
            return true;
        }
    }

    @PermitAll
    public static class PermitAllOnClass implements SimpleStub {
        public boolean callMe() {
            return true;
        }
    }

    public static class DenyAllOnMethod implements SimpleStub {
        @DenyAll
        public boolean callMe() {
            return false;
        }
    }

    @RolesAllowed("RoleOne")
    public static class  RolesAllowedOnClassDenyAllOnMethod implements SimpleStub {
        @DenyAll
        public boolean callMe() {
            return false;
        }
    }

    public static class  RolesAllowedOnMethodDenyAllOnMethod implements SimpleStub {
        @RolesAllowed("RoleOne")
        @DenyAll
        public boolean callMe() {
            return false;
        }
    }

    @RolesAllowed("RoleOne")
    @PermitAll
    public static class RolesAllowedOnClassPermitAllOnClass implements SimpleStub {
        public boolean callMe() {
            return true;
        }
    }

    public static class RolesAllowedOnMethodPermitAllOnMethod implements SimpleStub {
        @RolesAllowed("RoleOne")
        @PermitAll
        public boolean callMe() {
            return true;
        }
    }

    @RolesAllowed("RoleOne")
    public static class RolesAllowedOnClassPermitAllOnMethod implements SimpleStub {
        @PermitAll
        public boolean callMe() {
            return true;
        }
    }

    @PermitAll
    public static class PermitAllOnClassRolesAllowedOnMethod implements SimpleStub {
        @RolesAllowed("RoleOne")
        public boolean callMe() {
            return true;
        }
    }
}
