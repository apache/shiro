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

import static org.jboss.arquillian.graphene.Graphene.guardHttp;

import java.net.URL;
import java.util.List;

import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class LoginPage {
    @Drone
    private WebDriver webDriver;

    @ArquillianResource
    private URL baseURL;

    @FindBy(id = "username")
    private WebElement username;

    @FindBy(id = "password")
    private WebElement password;

    @FindBy(id = "login")
    private WebElement login;

    @FindBy(id = "login2")
    private WebElement nonJSFLogin;

    @FindBy(id = "rememberMe")
    private WebElement rememberMe;

    @FindBy(id = "sessionExpiredMessage")
    private WebElement sessionExpiredMessage;

    @FindBy(id = "loginFailureMessage")
    private WebElement loginFailureMessage;

    @FindBy(className = "shiro-form-data-notice")
    private List<WebElement> formDataNotices;

    @FindBy(name = "org.apache.shiro.form-data.discard")
    private WebElement discardFormData;

    public void goTo() {
        webDriver.get(baseURL + "shiro/auth/loginform");
    }

    public void login() {
        login("webuser", "webpwd");
    }

    public void login(String user, String pwd) {
        enterCredentials(user, pwd);
        guardHttp(login).click();
    }

    public void loginNonJSF() {
        enterCredentials("webuser", "webpwd");
        guardHttp(nonJSFLogin).click();
    }

    public void rememberMe() {
        if (!rememberMe.isSelected()) {
            rememberMe.click();
        }
    }

    public String sessionExpiredMessage() {
        return sessionExpiredMessage.getText();
    }

    public String loginFailureMessage() {
        return loginFailureMessage.getText();
    }

    public boolean hasFormDataNotice() {
        return !formDataNotices.isEmpty();
    }

    public String formDataNotice() {
        return formDataNotices.get(0).getText();
    }

    public boolean isDiscardFormDataSelected() {
        return discardFormData.isSelected();
    }

    public void discardSavedFormData() {
        discardFormData.click();
    }

    private void enterCredentials(String user, String pwd) {
        username.sendKeys(user);
        password.sendKeys(pwd);
    }
}
