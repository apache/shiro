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
package org.apache.shiro.testing.jakarta.ee.pages;

import java.net.URL;

import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class TagsPage {
    @Drone
    private WebDriver webDriver;

    @ArquillianResource
    private URL baseURL;

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

    public void goTo() {
        webDriver.get(baseURL + "shiro/unprotected/tags");
    }

    public String guest() {
        return guest.getText();
    }

    public String user() {
        return user.getText();
    }

    public String authenticated() {
        return authenticated.getText();
    }

    public String notAuthenticated() {
        return notAuthenticated.getText();
    }

    public String principal() {
        return principal.getText();
    }

    public String principalByType() {
        return principalByType.getText();
    }

    public String principalByProperty() {
        return principalByProperty.getText();
    }

    public String regularRole() {
        return regularRole.getText();
    }

    public String lacksAdminRole() {
        return lacksAdminRole.getText();
    }

    public String hasAnyRole() {
        return hasAnyRole.getText();
    }

    public String hasPermission() {
        return hasPermission.getText();
    }

    public String lacksPermission() {
        return lacksPermission.getText();
    }

    public String hasAnyPermission() {
        return hasAnyPermission.getText();
    }

    public String remembered() {
        return remembered.getText();
    }
}
