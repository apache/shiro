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

import java.net.URL;

import static org.apache.shiro.testing.jakarta.ee.ShiroAuthFormsIT.DEPLOYMENT_DEV_MODE;
import static org.apache.shiro.testing.jakarta.ee.ShiroAuthFormsIT.createDeploymentDev;
import static org.assertj.core.api.Assertions.assertThat;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.drone.api.annotation.Drone;

import static org.jboss.arquillian.graphene.Graphene.guardHttp;

import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

@ExtendWith(ArquillianExtension.class)
@Tag("UserInterface")
@Disabled("Failing with Cannot invoke \"org.jboss.arquillian.container.test.impl.domain"
    + ".ProtocolDefinition.createProtocolConfiguration()\" because \"protocolDefinition\" is null")
public class FacesTagsIT {
    @Drone
    private WebDriver webDriver;

    @SuppressWarnings("DeclarationOrder")
    @ArquillianResource
    protected URL baseURL;

    @FindBy(id = "username")
    private WebElement username;

    @FindBy(id = "password")
    private WebElement password;

    @FindBy(id = "login")
    private WebElement login;

    @FindBy(id = "guestTag")
    private WebElement guest;

    @FindBy(id = "userTag")
    private WebElement user;

    @FindBy(id = "authenticatedTag")
    private WebElement authenticated;

    @FindBy(id = "notAuthenticatedTag")
    private WebElement notAuthenticated;

    @FindBy(id = "principalTag")
    private WebElement principal;

    @FindBy(id = "principalTagByType")
    private WebElement principalByType;

    @FindBy(id = "principalTagByProperty")
    private WebElement principalByProperty;

    @FindBy(id = "hasRegularRoleTag")
    private WebElement regularRole;

    @FindBy(id = "lacksAdminRoleTag")
    private WebElement lacksAdminRole;

    @FindBy(id = "hasAnyRoleTag")
    private WebElement hasAnyRole;

    @FindBy(id = "hasPermissionTag")
    private WebElement hasPermission;

    @FindBy(id = "lacksPermissionTag")
    private WebElement lacksPermission;

    @FindBy(id = "hasAnyPermissionTag")
    private WebElement hasAnyPermission;

    @FindBy(id = "rememberedTag")
    private WebElement remembered;

    @BeforeEach
    void deleteAllCookies() {
        webDriver.manage().deleteAllCookies();
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void guestTag() {
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(guest.getText()).isEqualTo("Guest Content");
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(guest.getText()).isEqualTo("");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void userTag() {
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(user.getText()).isEqualTo("");
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(user.getText()).isEqualTo("User Content");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void authenticated() {
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(authenticated.getText()).isEqualTo("");
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(authenticated.getText()).isEqualTo("Authenticated Content");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void notAuthenticated() {
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(notAuthenticated.getText()).isEqualTo("Not Authenticated Content");
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(notAuthenticated.getText()).isEqualTo("");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principal() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(principal.getText()).isEqualTo("webuser");
    }

    @Test
    @SuppressWarnings("MagicNumber")
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principalByType() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(principalByType.getText()).isEqualTo("5");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principalByProperty() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(principalByProperty.getText()).isEqualTo("webuser");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasRegularRole() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(regularRole.getText()).isEqualTo("Regular Role");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void lacksAdminRole() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(lacksAdminRole.getText()).isEqualTo("Lacks Admin Role");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasAnyRole() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(hasAnyRole.getText()).isEqualTo("Has Some Role");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasAnyPermission() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(hasAnyPermission.getText()).isEqualTo("Has Some Permission");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasPermission() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(hasPermission.getText()).isEqualTo("Has Permission");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void lacksPermissio() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(lacksPermission.getText()).isEqualTo("Lacks Permission");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void remembered() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertThat(remembered.getText()).isEqualTo("");
    }

    private void login() {
        webDriver.get(baseURL + "shiro/auth/loginform");
        username.sendKeys("webuser");
        password.sendKeys("webpwd");
        guardHttp(login).click();
    }

    @Deployment(testable = false, name = DEPLOYMENT_DEV_MODE)
    public static WebArchive createDeployment() {
        return createDeploymentDev("shiro-facelet-tags.war");
    }
}
