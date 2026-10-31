/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.cdi;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.inject.spi.AnnotatedType;
import jakarta.enterprise.inject.spi.ProcessAnnotatedType;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler.AuthorizationConfigPolicy;
import org.apache.shiro.config.ConfigurationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ResourceLock("AuthorizationConfigPolicy.strictParsing")
class ShiroSecurityExtensionTest {
    @RequiresRoles({})
    interface EmptyRoles {
    }

    @RequiresPermissions({})
    static class EmptyPermissionsBase {
    }

    @Dependent
    static class EmptyRolesBean implements EmptyRoles {
    }

    @Dependent
    static class EmptyPermissionsBean extends EmptyPermissionsBase {
    }

    private boolean strictParsing;

    @BeforeEach
    void savePolicy() {
        strictParsing = AuthorizationConfigPolicy.isStrictParsing();
        AuthorizationConfigPolicy.setStrictParsing(false);
    }

    @AfterEach
    void restorePolicy() {
        AuthorizationConfigPolicy.setStrictParsing(strictParsing);
    }

    @Test
    void inheritedEmptyRolesAndPermissionsFollowSharedAuthorizationPolicy() {
        Logger logger = Logger.getLogger(AuthorizingAnnotationHandler.class.getName());
        var handler = new CapturingHandler();
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        try {
            assertThatCode(() -> process(EmptyRolesBean.class)).doesNotThrowAnyException();
            assertThatCode(() -> process(EmptyPermissionsBean.class)).doesNotThrowAnyException();
            assertThat(handler.records()).hasSize(2)
                    .allSatisfy(record -> assertThat(record.getLevel()).isEqualTo(Level.WARNING));

            AuthorizationConfigPolicy.setStrictParsing(true);
            assertThatExceptionOfType(ConfigurationException.class)
                    .isThrownBy(() -> process(EmptyRolesBean.class));
            assertThatExceptionOfType(ConfigurationException.class)
                    .isThrownBy(() -> process(EmptyPermissionsBean.class));
        } finally {
            logger.removeHandler(handler);
        }
    }

    @SuppressWarnings("unchecked")
    private static void process(Class<?> beanClass) {
        var pat = mock(ProcessAnnotatedType.class);
        var type = mock(AnnotatedType.class);
        when(type.getJavaClass()).thenReturn(beanClass);
        when(pat.getAnnotatedType()).thenReturn(type);
        new ShiroSecurityExtension().addInheritedSecurity(pat);
    }

    private static final class CapturingHandler extends Handler {
        private final List<LogRecord> records = new ArrayList<>();

        List<LogRecord> records() {
            return records;
        }

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    }
}
