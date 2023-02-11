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
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.drone.api.annotation.Drone;
import static org.jboss.arquillian.graphene.Graphene.guardHttp;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

@ExtendWith(ArquillianExtension.class)
@Tag("UserInterface")
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
        assertEquals("Guest Content", guest.getText());
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("", guest.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void userTag() {
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("", user.getText());
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("User Content", user.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void authenticated() {
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("", authenticated.getText());
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("Authenticated Content", authenticated.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void notAuthenticated() {
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("Not Authenticated Content", notAuthenticated.getText());
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("", notAuthenticated.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principal() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("webuser", principal.getText());
    }

    @Test
    @SuppressWarnings("MagicNumber")
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principalByType() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("5", principalByType.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void principalByProperty() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("webuser", principalByProperty.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasRegularRole() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("Regular Role", regularRole.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void lacksAdminRole() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("Lacks Admin Role", lacksAdminRole.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasAnyRole() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("Has Some Role", hasAnyRole.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasAnyPermission() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("Has Some Permission", hasAnyPermission.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void hasPermission() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("Has Permission" , hasPermission.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void lacksPermissio() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("Lacks Permission" , lacksPermission.getText());
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void remembered() {
        login();
        webDriver.get(baseURL + "shiro/unprotected/tags");
        assertEquals("" , remembered.getText());
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
