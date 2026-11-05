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

import com.flowlogix.util.ShrinkWrapManipulator;
import com.flowlogix.util.ShrinkWrapManipulator.Action;

import static com.flowlogix.util.ShrinkWrapManipulator.getContextParamValue;
import static org.apache.shiro.testing.jakarta.ee.Deployments.standardActions;
import static org.apache.shiro.testing.jakarta.ee.Deployments.isShiroNativeSessionsIntegrationTest;

import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.shiro.web.servlet.ShiroHttpSession.DEFAULT_SESSION_ID_NAME;
import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.testing.jakarta.ee.pages.FormPage;
import org.apache.shiro.testing.jakarta.ee.pages.LoginPage;
import org.apache.shiro.testing.jakarta.ee.pages.SessionControls;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.drone.api.annotation.Drone;

import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.FindBy;

/**
 * Form resubmit tests
 */
@ExtendWith(ArquillianExtension.class)
@Tag("UserInterface")
public class ShiroAuthFormsIT {
    static final String DEPLOYMENT_DEV_MODE = "DevMode";
    static final String DEPLOYMENT_PROD_MODE = "ProdMode";
    private static final String NATIVE_SESSION_COOKIE_NAME = "native_session_cookie";

    @Drone
    private WebDriver webDriver;

    @SuppressWarnings("DeclarationOrder")
    @ArquillianResource
    protected URL baseURL;

    @Page
    private LoginPage loginPage;

    @Page
    private FormPage formPage;

    @FindBy(tagName = "body")
    private SessionControls session;

    @BeforeEach
    void deleteAllCookies() {
        webDriver.manage().deleteAllCookies();
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void protectedPageWithLogin() {
        webDriver.get(baseURL + "shiro/protected");
        assertThat(webDriver.getCurrentUrl().contains("shiro/auth")).as("redirect to login").isTrue();
        loginPage.login();
        assertThat(webDriver.getTitle()).isEqualTo("Protected Page");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void checkLogout() {
        webDriver.get(baseURL + "shiro/protected");
        loginPage.login();
        session.logout();
        assertThat(webDriver.getCurrentUrl().contains("shiro/auth")).as("redirect to login").isTrue();
        loginPage.login();
        assertThat(webDriver.getTitle()).isEqualTo("Protected Page");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void nonJSFLogin() {
        webDriver.get(baseURL + "shiro/protected");
        loginPage.loginNonJSF();
        assertThat(webDriver.getTitle()).isEqualTo("Protected Page");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void logoutViaFilterThenLoginAndForm() {
        formPage.goTo();
        loginPage.loginNonJSF();
        session.logoutViaFilter();
        assertThat(webDriver.getCurrentUrl().contains("shiro/auth")).as("redirect to login").isTrue();
        loginPage.loginNonJSF();
        formPage.submitFirstForm("Jack", "Frost");
        assertThat(formPage.submissionMessage()).isEqualTo("Form Submitted - firstName: Jack, lastName: Frost");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void rememberMe() {
        webDriver.get(baseURL + "shiro/protected");
        loginPage.rememberMe();
        loginPage.login();
        webDriver.manage().deleteCookieNamed(isShiroNativeSessionsIntegrationTest()
                ? NATIVE_SESSION_COOKIE_NAME : DEFAULT_SESSION_ID_NAME);
        webDriver.navigate().refresh();
        assertThat(webDriver.getTitle()).isEqualTo("Protected Page");
        session.logout();
        assertThat(webDriver.getCurrentUrl().contains("shiro/auth")).as("redirect to login").isTrue();
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void unauthorized() {
        webDriver.get(baseURL + "shiro/adminpage");
        loginPage.login();
        assertThat(webDriver.getTitle()).isEqualTo("Unauthorized");
        session.logout();
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseURL + "index");
        webDriver.get(baseURL + "shiro/adminpage");
        loginPage.login("admin", "adminpwd");
        assertThat(webDriver.getTitle()).isEqualTo("Admin Page");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void incorrectLoginOnce() {
        webDriver.get(baseURL + "shiro/protected");
        loginPage.login("webuser", "wrongpwd");
        assertThat(loginPage.loginFailureMessage()).isEqualTo("Login Failed");
        loginPage.login();
        assertThat(webDriver.getTitle()).isEqualTo("Protected Page");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void nonAjaxSessionExpired() {
        nonAjaxSessionExpired("Jack", "Frost");
    }

    private void nonAjaxSessionExpired(String first, String last) {
        formPage.goTo();
        loginPage.login();
        session.invalidateSession();
        formPage.submitFirstForm(first, last);
        assertThat(loginPage.sessionExpiredMessage()).isEqualTo("Your Session Has Expired");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void nonAjaxResubmit() {
        nonAjaxSessionExpired();
        loginPage.login();
        assertThat(formPage.submissionMessage()).isEqualTo("Form Submitted - firstName: Jack, lastName: Frost");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void nonAjaxResubmitPreservesEscapedInput() {
        nonAjaxSessionExpired("Jörg & Sons + =", "Frost 雪");
        loginPage.login();
        assertThat(formPage.submissionMessage()).isEqualTo("Form Submitted - firstName: Jörg & Sons + =, lastName: Frost 雪");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void formDataNoticeOnlyWhenFormDataIsSaved() {
        webDriver.get(baseURL + "shiro/protected");
        assertThat(loginPage.hasFormDataNotice()).isFalse();
        nonAjaxSessionExpired();
        assertThat(loginPage.formDataNotice()).startsWith("We saved the form data you entered");
        assertThat(loginPage.isDiscardFormDataSelected()).isFalse();
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void discardSavedFormData() {
        nonAjaxSessionExpired();
        loginPage.discardSavedFormData();
        loginPage.login();
        assertThat(webDriver.getTitle()).isEqualTo("Form Page");
        assertThat(formPage.hasSubmissionMessage()).as("no form data submitted").isFalse();
        assertThat(formPage.firstName()).isEmpty();
        loginPage.goTo();
        assertThat(loginPage.hasFormDataNotice()).as("discarded").isFalse();
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void nonAjaxResubmitAfterFailedLogin() {
        nonAjaxSessionExpired();
        loginPage.login("xxx", "yyy");
        loginPage.login();
        assertThat(formPage.submissionMessage()).isEqualTo("Form Submitted - firstName: Jack, lastName: Frost");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void nonAjaxRememberedResubmit() {
        formPage.goTo();
        loginPage.rememberMe();
        loginPage.login();
        session.invalidateSession();
        formPage.submitFirstForm("Jack", "Frost");
        assertThat(formPage.submissionMessage()).isEqualTo("Form Submitted - firstName: Jack, lastName: Frost");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void ajaxSessionExpired() {
        formPage.goTo();
        loginPage.login();
        session.invalidateSession();
        formPage.fillSecondForm("1 Houston Street", "New York");
        formPage.submitSecondFormWithRedirect();
        assertThat(loginPage.sessionExpiredMessage()).isEqualTo("Your Session Has Expired");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void ajaxResubmit() {
        ajaxSessionExpired();
        loginPage.login();
        assertThat(formPage.secondFormMessage()).isEqualTo("2nd Form Submitted - Address: 1 Houston Street, City: New York");
        formPage.fillSecondForm("Workshop", "North Pole");
        formPage.submitSecondForm();
        assertThat(formPage.secondFormMessage()).isEqualTo("2nd Form Submitted - Address: Workshop, City: North Pole");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void ajaxRememberedResubmit() {
        formPage.goTo();
        loginPage.rememberMe();
        loginPage.login();
        formPage.fillSecondForm("1 Houston Street", "New York");
        session.invalidateSession();
        formPage.submitSecondForm();
        formPage.clearSecondForm();
        assertThat(formPage.secondFormMessage()).isEqualTo("2nd Form Submitted - Address: 1 Houston Street, City: New York");
        formPage.fillSecondForm("Workshop", "North Pole");
        session.invalidateSession();
        formPage.submitSecondForm();
        formPage.clearSecondForm();
        assertThat(formPage.secondFormMessage()).isEqualTo("2nd Form Submitted - Address: Workshop, City: North Pole");
        formPage.fillSecondForm("LAX Airport", "Los Angeles");
        formPage.submitSecondForm();
        assertThat(formPage.secondFormMessage()).isEqualTo("2nd Form Submitted - Address: LAX Airport, City: Los Angeles");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void nonAjaxAnonymousResubmit() {
        formPage.goToAnonymous();
        assertThat(webDriver.getTitle()).isEqualTo("Anonymous Form Page");
        expireAnonymousSession();
        formPage.submitFirstForm("Jack", "Frost");
        assertThat(webDriver.getTitle()).as("no login page").isEqualTo("Anonymous Form Page");
        assertThat(formPage.firstFormMessage()).isEqualTo("Anonymous Form Submitted - firstName: Jack, lastName: Frost");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void ajaxAnonymousResubmit() {
        formPage.goToAnonymous();
        formPage.fillSecondForm("1 Houston Street", "New York");
        expireAnonymousSession();
        formPage.submitSecondForm();
        assertThat(webDriver.getTitle()).as("no login page").isEqualTo("Anonymous Form Page");
        assertThat(formPage.secondFormMessage())
                .isEqualTo("2nd Anonymous Form Submitted - Address: 1 Houston Street, City: New York");
        formPage.clearSecondForm();
        formPage.fillSecondForm("Workshop", "North Pole");
        formPage.submitSecondForm();
        assertThat(formPage.secondFormMessage())
                .isEqualTo("2nd Anonymous Form Submitted - Address: Workshop, City: North Pole");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void alreadyLoggedIn() {
        formPage.goTo();
        loginPage.login();
        loginPage.goTo();
        loginPage.login();
        assertThat(webDriver.getTitle()).isEqualTo("Index");
    }

    /**
     * Simulates a timed-out anonymous session. Explicit invalidation of a native session also removes
     * its cookie from the browser, unlike a timeout, after which the browser still sends the stale id,
     * so the stale cookie is restored here.
     */
    private void expireAnonymousSession() {
        var sessionCookie = webDriver.manage().getCookieNamed(NATIVE_SESSION_COOKIE_NAME);
        session.invalidateSession();
        if (isShiroNativeSessionsIntegrationTest() && sessionCookie != null) {
            // Firefox rejects re-adding the cookie with its original attributes (e.g. secure) over plain HTTP
            webDriver.manage().addCookie(new Cookie(sessionCookie.getName(), sessionCookie.getValue(),
                    sessionCookie.getPath()));
        }
    }

    @Deployment(testable = false, name = DEPLOYMENT_DEV_MODE)
    public static WebArchive createDeployment() {
        return createDeploymentDev("shiro-auth-forms");
    }

    static WebArchive createDeploymentDev(String archiveName) {
        var archive = ShrinkWrapManipulator.<WebArchive>createDeployment(name -> "%s-%s".formatted(name, archiveName))
                .deletePackage("org.apache.shiro.testing.jaxrs");
        new ShrinkWrapManipulator().webXmlXPath(archive, standardActions);
        return archive;
    }

    @Deployment(testable = false, name = DEPLOYMENT_PROD_MODE)
    public static WebArchive createDeploymentProd() {
        return createDeploymentProd("shiro-auth-forms-prod");
    }

    static WebArchive createDeploymentProd(String archiveName) {
        var archive = ShrinkWrapManipulator.<WebArchive>createDeployment(name -> "%s-%s".formatted(name, archiveName))
                .deletePackage("org.apache.shiro.testing.jaxrs");
        var productionList = List.of(new Action(
                getContextParamValue("jakarta.faces.PROJECT_STAGE"),
                node -> node.setTextContent("Production")));
        new ShrinkWrapManipulator().webXmlXPath(archive, Stream.concat(productionList.stream(),
                standardActions.stream()).collect(Collectors.toList()));
        return archive;
    }
}
