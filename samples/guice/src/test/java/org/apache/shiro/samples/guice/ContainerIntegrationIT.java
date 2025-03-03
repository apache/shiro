/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.samples.guice;

import com.github.mjeanroy.junit.servers.jetty12.EmbeddedJetty;
import org.apache.shiro.testing.web.AbstractContainerIT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.htmlunit.ElementNotFoundException;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.WebAssert;
import org.htmlunit.html.HtmlCheckBoxInput;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;

import java.io.IOException;
import java.net.MalformedURLException;

public class ContainerIntegrationIT extends AbstractContainerIT {

    @BeforeEach
    public void logOut() throws IOException {
        // Make sure we are logged out
        final HtmlPage homePage = webClient.getPage(getBaseUri());
        try {
            homePage.getAnchorByHref("/logout").click();
        } catch (ElementNotFoundException e) {
            //Ignore
        }
    }

    @Test
    void logIn() throws FailingHttpStatusCodeException, MalformedURLException, IOException, InterruptedException {

        HtmlPage page = webClient.getPage(getBaseUri() + "login.jsp");
        HtmlForm form = page.getFormByName("loginform");
        form.getInputByName("username").setValueAttribute("root");
        form.getInputByName("password").setValueAttribute("secret");
        page = form.getInputByName("submit").click();
        // This'll throw an exception if not logged in
        page.getAnchorByHref("/logout");
    }

    @Test
    void logInAndRememberMe(EmbeddedJetty jetty) throws Exception {
        HtmlPage page = webClient.getPage(getBaseUri() + "login.jsp");
        HtmlForm form = page.getFormByName("loginform");
        form.getInputByName("username").setValueAttribute("root");
        form.getInputByName("password").setValueAttribute("secret");
        HtmlCheckBoxInput checkbox = form.getInputByName("rememberMe");
        checkbox.setChecked(true);
        page = form.getInputByName("submit").click();
        jetty.stop();
        jetty.start();
        page = webClient.getPage(getBaseUri());
        // page.getAnchorByHref("/logout");
        WebAssert.assertLinkPresentWithText(page, "Log out");
        page = page.getAnchorByHref("/account").click();
        // login page should be shown again - user remembered but not authenticated
        WebAssert.assertFormPresent(page, "loginform");
    }

}
