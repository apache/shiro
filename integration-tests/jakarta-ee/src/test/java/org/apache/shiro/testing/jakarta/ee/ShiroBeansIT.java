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
import static org.assertj.core.api.Assertions.assertThat;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.drone.api.annotation.Drone;

import static org.jboss.arquillian.graphene.Graphene.guardAjax;
import static org.jboss.arquillian.graphene.Graphene.guardHttp;
import static org.jboss.arquillian.graphene.Graphene.waitGui;

import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.ui.ExpectedConditions;

/**
 * Protected EJB/CDI beans tests
 */
@ExtendWith(ArquillianExtension.class)
@Tag("UserInterface")
public class ShiroBeansIT {
    @Drone
    private WebDriver webDriver;

    @SuppressWarnings("DeclarationOrder")
    @ArquillianResource
    protected URL baseURL;

    @FindBy(id = "form:facesViewScoped")
    private WebElement facesViewScoped;

    @FindBy(id = "form:omniViewScoped")
    private WebElement omniViewScoped;

    @FindBy(id = "form:sessionScoped")
    private WebElement sessionScoped;

    @FindBy(id = "form:stateless")
    private WebElement stateless;

    @FindBy(id = "form:unprotected")
    private WebElement unprotectedMethod;

    @FindBy(id = "form:protected")
    private WebElement protectedMethod;

    @FindBy(id = "invalidate")
    private WebElement invalidateSession;

    @FindBy(id = "form:messages")
    private WebElement messages;

    @FindBy(id = "username")
    private WebElement username;

    @FindBy(id = "password")
    private WebElement password;

    @FindBy(id = "login")
    private WebElement login;

    @FindBy(id = "usingWebSessions")
    private WebElement usingWebSessions;

    @BeforeEach
    void deleteAllCookies() {
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseURL + "api/statistics/clear");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void checkDontCallWhenNotAuth() {
        webDriver.get(baseURL + "shiro/unprotected/manybeans");
        guardAjax(facesViewScoped).click();
        assertThat(messages.getText()).startsWith("view scope unauth: Attempting to perform a user-only operation");
        guardAjax(omniViewScoped).click();
        assertThat(messages.getText()).startsWith("omni view scope unauth: Attempting to perform a user-only operation");
        guardAjax(sessionScoped).click();
        assertThat(messages.getText()).startsWith("session scoped unauth: Attempting to perform a user-only operation");
        guardAjax(stateless).click();
        assertThat(messages.getText()).startsWith("stateless bean unauth: Attempting to perform a user-only operation");
        guardAjax(unprotectedMethod).click();
        assertThat(messages.getText()).isEqualTo("unprotected method: hello from unprotected");
        guardAjax(protectedMethod).click();
        assertThat(messages.getText()).startsWith("protected unauth: Attempting to perform a user-only operation");
        webDriver.get(baseURL + "lastException");
        String exceptionText = webDriver.findElement(By.tagName("body")).getText();
        assertThat(exceptionText).startsWith(
                "WARNING: jakarta.ejb.EJBException: Attempting to perform a user-only operation");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void checkCallWhenAuth() {
        webDriver.get(baseURL + "shiro/auth/loginform");
        login();

        webDriver.get(baseURL + "shiro/unprotected/manybeans");
        guardAjax(facesViewScoped).click();
        assertThat(messages.getText()).startsWith("Hello from FacesViewScoped");
        guardAjax(omniViewScoped).click();
        assertThat(messages.getText()).startsWith("Hello from OmniViewScoped");
        guardAjax(sessionScoped).click();
        assertThat(messages.getText()).startsWith("Hello from SessionScoped");
        guardAjax(stateless).click();
        assertThat(messages.getText()).startsWith("Hello from ProtectedStatelessBean");
        guardAjax(protectedMethod).click();
        assertThat(messages.getText()).isEqualTo("protected method: hello from protected");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void beanDestroyCalled() {
        exersizeViewAndSessionScoped(facesViewScoped, "api/statistics/pc_fv", "api/statistics/pd_fv");
        webDriver.get(baseURL + "api/statistics/clear");
        exersizeViewAndSessionScoped(omniViewScoped, "api/statistics/pc_ofv", "api/statistics/pd_ofv");
    }

    private void exersizeViewAndSessionScoped(WebElement elem, String createStatistic, String destroyStatistic) {
        webDriver.get(baseURL + "shiro/auth/loginform");
        login();

        webDriver.get(baseURL + "shiro/unprotected/manybeans");
        boolean webSessions = Boolean.parseBoolean(usingWebSessions.getText());
        guardAjax(elem).click();
        webDriver.navigate().refresh();
        guardAjax(elem).click();
        guardAjax(sessionScoped).click();

        invalidateSession.click();
        waitGui(webDriver).until(ExpectedConditions.alertIsPresent());
        webDriver.switchTo().alert().accept();
        webDriver.get(baseURL + createStatistic);
        assertThat(webDriver.findElement(By.tagName("body")).getText()).isEqualTo("2");
        webDriver.get(baseURL + destroyStatistic);
        assertThat(webDriver.findElement(By.tagName("body")).getText()).isEqualTo("2");
        webDriver.get(baseURL + "api/statistics/pc_ss");
        assertThat(webDriver.findElement(By.tagName("body")).getText()).isEqualTo("1");
        webDriver.get(baseURL + "api/statistics/pd_ss");
        assertThat(webDriver.findElement(By.tagName("body")).getText()).isEqualTo("1");
    }

    private void login() {
        username.sendKeys("webuser");
        password.sendKeys("webpwd");
        guardHttp(login).click();
    }

    @Deployment(testable = false, name = DEPLOYMENT_DEV_MODE)
    public static WebArchive createDeployment() {
        return ShiroAuthFormsIT.createDeploymentDev("shiro-beans-test.war");
    }
}
