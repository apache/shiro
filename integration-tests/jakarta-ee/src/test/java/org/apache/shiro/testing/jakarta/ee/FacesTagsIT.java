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
package org.apache.shiro.testing.jakarta.ee;

import static org.apache.shiro.testing.jakarta.ee.ShiroAuthFormsIT.DEPLOYMENT_DEV_MODE;
import static org.apache.shiro.testing.jakarta.ee.ShiroAuthFormsIT.createDeploymentDev;
import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.testing.jakarta.ee.pages.LoginPage;
import org.apache.shiro.testing.jakarta.ee.pages.TagsPage;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.drone.api.annotation.Drone;

import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.shrinkwrap.api.spec.WebArchive;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.WebDriver;

@ExtendWith(ArquillianExtension.class)
@Tag("UserInterface")
public class FacesTagsIT {
    @Drone
    private WebDriver webDriver;

    @Page
    private LoginPage loginPage;

    @Page
    private TagsPage tagsPage;

    @BeforeEach
    void deleteAllCookies() {
        webDriver.manage().deleteAllCookies();
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void guestTag() {
        tagsPage.goTo();
        assertThat(tagsPage.guest()).isEqualTo("Guest Content");
        login();
        tagsPage.goTo();
        assertThat(tagsPage.guest()).isEqualTo("");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void userTag() {
        tagsPage.goTo();
        assertThat(tagsPage.user()).isEqualTo("");
        login();
        tagsPage.goTo();
        assertThat(tagsPage.user()).isEqualTo("User Content");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void authenticated() {
        tagsPage.goTo();
        assertThat(tagsPage.authenticated()).isEqualTo("");
        login();
        tagsPage.goTo();
        assertThat(tagsPage.authenticated()).isEqualTo("Authenticated Content");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void notAuthenticated() {
        tagsPage.goTo();
        assertThat(tagsPage.notAuthenticated()).isEqualTo("Not Authenticated Content");
        login();
        tagsPage.goTo();
        assertThat(tagsPage.notAuthenticated()).isEqualTo("");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principal() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.principal()).isEqualTo("webuser");
    }

    @Test
    @SuppressWarnings("MagicNumber")
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principalByType() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.principalByType()).isEqualTo("5");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principalByProperty() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.principalByProperty()).isEqualTo("webuser");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasRegularRole() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.regularRole()).isEqualTo("Regular Role");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void lacksAdminRole() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.lacksAdminRole()).isEqualTo("Lacks Admin Role");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasAnyRole() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.hasAnyRole()).isEqualTo("Has Some Role");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasAnyPermission() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.hasAnyPermission()).isEqualTo("Has Some Permission");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasPermission() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.hasPermission()).isEqualTo("Has Permission");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void lacksPermissio() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.lacksPermission()).isEqualTo("Lacks Permission");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void remembered() {
        login();
        tagsPage.goTo();
        assertThat(tagsPage.remembered()).isEqualTo("");
    }

    private void login() {
        loginPage.goTo();
        loginPage.login();
    }

    @Deployment(testable = false, name = DEPLOYMENT_DEV_MODE)
    public static WebArchive createDeployment() {
        return createDeploymentDev("shiro-facelet-tags");
    }
}
