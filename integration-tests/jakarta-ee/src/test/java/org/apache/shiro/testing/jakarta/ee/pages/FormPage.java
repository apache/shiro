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
import static org.jboss.arquillian.graphene.Graphene.guardHttp;
import static org.jboss.arquillian.graphene.Graphene.waitForHttp;

import java.net.URL;
import java.util.List;

import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class FormPage {
    @Drone
    private WebDriver webDriver;

    @ArquillianResource
    private URL baseURL;

    @FindBy(id = "firstForm:firstName")
    private WebElement firstName;

    @FindBy(id = "firstForm:lastName")
    private WebElement lastName;

    @FindBy(id = "firstForm:submitFirst")
    private WebElement submitFirst;

    @FindBy(id = "secondForm:address")
    private WebElement address;

    @FindBy(id = "secondForm:city")
    private WebElement city;

    @FindBy(id = "secondForm:submitSecond")
    private WebElement submitSecond;

    @FindBy(id = "secondForm:messages")
    private WebElement secondFormMessages;

    @FindBy(id = "firstForm:messages")
    private WebElement firstFormMessages;

    @FindBy(id = "messages")
    private List<WebElement> submissionMessages;

    public void goTo() {
        webDriver.get(baseURL + "shiro/form");
    }

    public void goToAnonymous() {
        webDriver.get(baseURL + "shiro/unprotected/form");
    }

    public void submitFirstForm(String first, String last) {
        firstName.sendKeys(first);
        lastName.sendKeys(last);
        guardHttp(submitFirst).click();
    }

    public void fillSecondForm(String street, String town) {
        address.sendKeys(street);
        city.sendKeys(town);
    }

    public void clearSecondForm() {
        address.clear();
        city.clear();
    }

    public void submitSecondForm() {
        guardAjax(submitSecond).click();
    }

    public void submitSecondFormWithRedirect() {
        waitForHttp(submitSecond).click();
    }

    public String firstName() {
        return firstName.getAttribute("value");
    }

    public String firstFormMessage() {
        return firstFormMessages.getText();
    }

    public String secondFormMessage() {
        return secondFormMessages.getText();
    }

    public boolean hasSubmissionMessage() {
        return !submissionMessages.isEmpty();
    }

    public String submissionMessage() {
        return submissionMessages.get(0).getText();
    }
}
