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
package org.apache.shiro.guice.aop;

import com.google.inject.Guice;
import com.google.inject.Injector;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClassLevelSuperclassAnnotatedTest {
    private final Injector injector = Guice.createInjector(new ShiroAopModule());

    @Test
    void overriddenMethodExecutesForUserWithoutRequiredRole() {
        Subject subject = login("alice");
        OverridingService service = injector.getInstance(OverridingService.class);
        subject.execute(() -> {
            assertThatThrownBy(service::adminOnlyData)
                    .isInstanceOf(AuthorizationException.class);

            assertThatThrownBy(service::directlyProtected)
                    .isInstanceOf(AuthorizationException.class);
        });
    }

    @Test
    void inheritedMethodStillExecutesTheSuperclassCheck() {
        Subject subject = login("alice");
        InheritedService service = injector.getInstance(InheritedService.class);
        subject.execute(() -> {
            assertThatThrownBy(service::adminOnlyData)
                    .isInstanceOf(AuthorizationException.class);
        });
    }

    @Test
    void adminCanExecuteTheOverriddenMethod() {
        Subject subject = login("admin");
        OverridingService service = injector.getInstance(OverridingService.class);
        subject.execute(() -> {
            assertThat(service.adminOnlyData()).isEqualTo("ADMIN_ONLY_DATA");
        });
    }

    private Subject login(String username) {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.addAccount("alice", "pw", "user");
        realm.addAccount("admin", "pw", "admin");
        Subject subject = new Subject.Builder(new DefaultSecurityManager(realm)).buildSubject();
        subject.login(new UsernamePasswordToken(username, "pw"));
        return subject;
    }

    @RequiresRoles("admin")
    public static class ParentService {
        public String adminOnlyData() {
            return "PARENT_ADMIN_ONLY_DATA";
        }
    }

    public static class OverridingService extends ParentService {
        @Override
        public String adminOnlyData() {
            return "ADMIN_ONLY_DATA";
        }

        @RequiresRoles("admin")
        public void directlyProtected() {
        }
    }

    public static class InheritedService extends ParentService {
    }
}
