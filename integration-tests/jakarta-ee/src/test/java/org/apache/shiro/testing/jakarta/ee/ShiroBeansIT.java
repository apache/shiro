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

import org.apache.shiro.testing.jakarta.ee.pages.LoginPage;
import org.apache.shiro.testing.jakarta.ee.pages.ManyBeansPage;
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
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.FindBy;

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

    @Page
    private LoginPage loginPage;

    @Page
    private ManyBeansPage manyBeansPage;

    @FindBy(tagName = "body")
    private SessionControls session;

    @BeforeEach
    void deleteAllCookies() {
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseURL + "api/statistics/clear");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void checkDontCallWhenNotAuth() {
        manyBeansPage.goTo();
        manyBeansPage.callFacesViewScoped();
        assertThat(manyBeansPage.message()).startsWith("view scope unauth: Attempting to perform a user-only operation");
        manyBeansPage.callOmniViewScoped();
        assertThat(manyBeansPage.message()).startsWith("omni view scope unauth: Attempting to perform a user-only operation");
        manyBeansPage.callSessionScoped();
        assertThat(manyBeansPage.message()).startsWith("session scoped unauth: Attempting to perform a user-only operation");
        manyBeansPage.callStateless();
        assertThat(manyBeansPage.message()).startsWith("stateless bean unauth: Attempting to perform a user-only operation");
        manyBeansPage.callUnprotectedMethod();
        assertThat(manyBeansPage.message()).isEqualTo("unprotected method: hello from unprotected");
        manyBeansPage.callProtectedMethod();
        assertThat(manyBeansPage.message()).startsWith("protected unauth: Attempting to perform a user-only operation");
        manyBeansPage.callViaInterface();
        assertThat(manyBeansPage.message()).startsWith("via interface unauth: Attempting to perform a user-only operation");
        manyBeansPage.callViaInterfaceMethod();
        assertThat(manyBeansPage.message())
                .startsWith("via interface method unauth: Attempting to perform a user-only operation");
        manyBeansPage.callViaSuperclass();
        assertThat(manyBeansPage.message()).startsWith("via superclass unauth: Attempting to perform a user-only operation");
        webDriver.get(baseURL + "lastException");
        String exceptionText = webDriver.findElement(By.tagName("body")).getText();
        assertThat(exceptionText).startsWith(
                "WARNING: jakarta.ejb.EJBException: Attempting to perform a user-only operation");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void checkCallWhenAuth() {
        loginPage.goTo();
        loginPage.login();

        manyBeansPage.goTo();
        manyBeansPage.callFacesViewScoped();
        assertThat(manyBeansPage.message()).startsWith("Hello from FacesViewScoped");
        manyBeansPage.callOmniViewScoped();
        assertThat(manyBeansPage.message()).startsWith("Hello from OmniViewScoped");
        manyBeansPage.callSessionScoped();
        assertThat(manyBeansPage.message()).startsWith("Hello from SessionScoped");
        manyBeansPage.callStateless();
        assertThat(manyBeansPage.message()).startsWith("Hello from ProtectedStatelessBean");
        manyBeansPage.callProtectedMethod();
        assertThat(manyBeansPage.message()).isEqualTo("protected method: hello from protected");
        manyBeansPage.callViaInterface();
        assertThat(manyBeansPage.message()).isEqualTo("Hello from ProtectedViaInterfaceBean");
        manyBeansPage.callViaInterfaceMethod();
        assertThat(manyBeansPage.message()).isEqualTo("Unprotected hello from ProtectedViaInterfaceMethodBean"
                + " / Hello from ProtectedViaInterfaceMethodBean");
        manyBeansPage.callViaSuperclass();
        assertThat(manyBeansPage.message()).isEqualTo("Hello from ProtectedViaSuperclassBean");
    }

    @Test
    @OperateOnDeployment(DEPLOYMENT_DEV_MODE)
    void beanDestroyCalled() {
        exerciseViewAndSessionScoped(manyBeansPage::callFacesViewScoped, "api/statistics/pc_fv", "api/statistics/pd_fv");
        webDriver.get(baseURL + "api/statistics/clear");
        exerciseViewAndSessionScoped(manyBeansPage::callOmniViewScoped, "api/statistics/pc_ofv", "api/statistics/pd_ofv");
    }

    private void exerciseViewAndSessionScoped(Runnable callBean, String createStatistic, String destroyStatistic) {
        loginPage.goTo();
        loginPage.login();

        manyBeansPage.goTo();
        callBean.run();
        webDriver.navigate().refresh();
        callBean.run();
        manyBeansPage.callSessionScoped();

        session.invalidateSession();
        webDriver.get(baseURL + createStatistic);
        assertThat(webDriver.findElement(By.tagName("body")).getText()).isEqualTo("2");
        webDriver.get(baseURL + destroyStatistic);
        assertThat(webDriver.findElement(By.tagName("body")).getText()).isEqualTo("2");
        webDriver.get(baseURL + "api/statistics/pc_ss");
        assertThat(webDriver.findElement(By.tagName("body")).getText()).isEqualTo("1");
        webDriver.get(baseURL + "api/statistics/pd_ss");
        assertThat(webDriver.findElement(By.tagName("body")).getText()).isEqualTo("1");
    }

    @Deployment(testable = false, name = DEPLOYMENT_DEV_MODE)
    public static WebArchive createDeployment() {
        return ShiroAuthFormsIT.createDeploymentDev("shiro-beans-test");
    }
}
