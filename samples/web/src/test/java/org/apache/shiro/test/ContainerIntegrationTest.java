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
package org.apache.shiro.test;

import java.io.IOException;
import java.net.MalformedURLException;

import org.junit.Before;
import org.junit.Test;

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebAssert;
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

public class ContainerIntegrationTest extends AbstractContainerTest {

    @Before
    public void logOut() throws IOException {
        // Make sure we are logged out
        final HtmlPage homePage = webClient.getPage(BASEURI);
        try {
            homePage.getAnchorByHref("/logout.jsp").click();
        }
        catch (ElementNotFoundException e) {
            //Ignore
        }
    }

    @Test
    public void logIn() throws FailingHttpStatusCodeException, MalformedURLException, IOException, InterruptedException {

        HtmlPage page = webClient.getPage(BASEURI + "login.jsp");
        HtmlForm form = page.getFormByName("loginform");
        form.getInputByName("username").setValueAttribute("root");
        form.getInputByName("password").setValueAttribute("secret");
        page = form.getInputByName("submit").click();
        // This'll throw an expection if not logged in
        page.getAnchorByHref("/logout.jsp");
    }

    @Test
    public void logInAndRememberMe() throws Exception {
        HtmlPage page = webClient.getPage(BASEURI + "login.jsp");
        HtmlForm form = page.getFormByName("loginform");
        form.getInputByName("username").setValueAttribute("root");
        form.getInputByName("password").setValueAttribute("secret");
        HtmlCheckBoxInput checkbox = form.getInputByName("rememberMe");
        checkbox.setChecked(true);
        page = form.getInputByName("submit").click();
        server.stop();
        server.start();
        page = webClient.getPage(BASEURI);
        // page.getAnchorByHref("/logout.jsp");
        WebAssert.assertLinkPresentWithText(page, "Log out");
        page = page.getAnchorByHref("/account").click();
        // login page should be shown again - user remembered but not authenticated
        WebAssert.assertFormPresent(page, "loginform");
    }

}
