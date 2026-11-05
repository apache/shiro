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

import static org.jboss.arquillian.graphene.Graphene.guardAjax;

import java.net.URL;

import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class ManyBeansPage {
    @Drone
    private WebDriver webDriver;

    @ArquillianResource
    private URL baseURL;

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

    @FindBy(id = "form:viaInterface")
    private WebElement viaInterface;

    @FindBy(id = "form:viaInterfaceMethod")
    private WebElement viaInterfaceMethod;

    @FindBy(id = "form:viaSuperclass")
    private WebElement viaSuperclass;

    @FindBy(id = "form:messages")
    private WebElement messages;

    public void goTo() {
        webDriver.get(baseURL + "shiro/unprotected/manybeans");
    }

    public void callFacesViewScoped() {
        guardAjax(facesViewScoped).click();
    }

    public void callOmniViewScoped() {
        guardAjax(omniViewScoped).click();
    }

    public void callSessionScoped() {
        guardAjax(sessionScoped).click();
    }

    public void callStateless() {
        guardAjax(stateless).click();
    }

    public void callUnprotectedMethod() {
        guardAjax(unprotectedMethod).click();
    }

    public void callProtectedMethod() {
        guardAjax(protectedMethod).click();
    }

    public void callViaInterface() {
        guardAjax(viaInterface).click();
    }

    public void callViaInterfaceMethod() {
        guardAjax(viaInterfaceMethod).click();
    }

    public void callViaSuperclass() {
        guardAjax(viaSuperclass).click();
    }

    public String message() {
        return messages.getText();
    }
}
