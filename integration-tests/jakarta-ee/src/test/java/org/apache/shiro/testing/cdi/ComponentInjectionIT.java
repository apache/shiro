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
package org.apache.shiro.testing.cdi;

import javax.inject.Inject;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;

import static org.apache.shiro.ee.util.JakartaTransformer.jakartify;
import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.testing.jakarta.ee.PropertyPrincipal;
import org.apache.shiro.testing.jaxrs.NoIniJaxRsIT;
import org.apache.shiro.testing.jaxrs.TestApplication;
import org.apache.shiro.util.ThreadContext;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.util.Optional;

/**
 * Tests @Injecting Subject, Session, Principal and SecurityManager with CDI
 */
@ExtendWith(ArquillianExtension.class)
@Execution(ExecutionMode.SAME_THREAD)
@Slf4j
public class ComponentInjectionIT {
    @SuppressWarnings("JavadocVariable")
    public static final String TESTABLE_MODE = "TestableMode";

    @Inject
    ComponentInjectionBean injectedComponents;
    @Inject
    TestApplication testApplication;

    @BeforeEach
    void bind() {
        ThreadContext.bind(testApplication.getSecurityManager());
    }

    @AfterEach
    void unbind() {
        SecurityUtils.getSubject().logout();
        ThreadContext.unbindSecurityManager();
        ThreadContext.unbindSubject();
        ThreadContext.remove();
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void securityManagerInjection() {
        assertThat(injectedComponents.getSecurityManager()).isNotNull();
        assertThat(injectedComponents.getSecurityManager().getSession(() -> null)).isNull();
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void subjectInjection() {
        assertThat(injectedComponents.getSubject()).isNotNull();
        assertThat(injectedComponents.getSubject().getPrincipal()).isNull();
        assertThat(injectedComponents.getSubject().isAuthenticated()).isFalse();
        UsernamePasswordToken token = new UsernamePasswordToken("user", "password");
        injectedComponents.getSubject().login(token);
        assertThat(injectedComponents.getSubject().isAuthenticated()).isTrue();

        injectedComponents.getSubject().logout();
        assertThat(injectedComponents.getSubject().isAuthenticated()).isFalse();
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void sessionInjection() {
        assertThat(injectedComponents.getSession()).isNotNull();
        assertThat(injectedComponents.getNoCreateionSession()).isNotNull();
        injectedComponents.getSession().setAttribute("hello", "bye");
        assertThat(injectedComponents.getSession().getAttribute("hello")).isEqualTo("bye");
        assertThat(injectedComponents.getNoCreateionSession().getAttribute("hello")).isEqualTo("bye");
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void principalInjection() {
        SecurityUtils.getSubject().login(new UsernamePasswordToken("user", "password"));
        assertThat(injectedComponents.getPropertyPrincipal()).isNotNull();
        assertThat(Optional.ofNullable(injectedComponents.getPropertyPrincipal().get()).orElseThrow().getUserName())
            .isEqualTo("user");
        injectedComponents.getSubject().logout();
    }

    @Deployment(name = TESTABLE_MODE)
    public static WebArchive createDeployment() {
        return createDeployment("security-manager-injection.war");
    }

    public static WebArchive createDeployment(String archive) {
        var webArchive = ShrinkWrap.create(WebArchive.class, archive)
                .addAsResource("META-INF/beans.xml")
                .addAsResource(new StringAsset("org.apache.shiro.cdi.ShiroSecurityExtension"),
                        jakartify("META-INF/services/javax.enterprise.inject.spi.Extension"))
                .addAsResource("META-INF/services/org.slf4j.spi.SLF4JServiceProvider")
                .addAsWebInfResource(new StringAsset(
                        "<payara-web-app><class-loader delegate=\"false\"/></payara-web-app>"),
                        "payara-web.xml")
                .addPackages(true, "org.apache.shiro")
                .addPackages(true, "org.apache.commons")
                .deletePackages(true, "org.apache.shiro.testing")
                .deletePackages(true, "org.apache.shiro.ee")
                .addClass(ComponentInjectionIT.class)
                .addPackages(true, "org.apache.shiro.testing.jaxrs")
                .addPackage("org.apache.shiro.ee.util")
                .addClass(NoIniJaxRsIT.class)
                .addClass(PropertyPrincipal.class)
                .addClass(ComponentInjectionBean.class)
                .addPackages(true, "org.assertj.core")
                .addPackages(true, "org.slf4j");
        log.debug("Archive contents for {}: {}", archive, webArchive.toString(true));
        return webArchive;
    }
}
