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

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.apache.shiro.testing.web.AbstractContainerIT;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.MalformedURLException;

public class WebAppContainerIntegrationIT extends AbstractContainerIT {

    protected final WebClient webClient = new WebClient();

    @Before
    public void logOut() throws IOException {
        // Make sure we are logged out
        final HtmlPage homePage = webClient.getPage(getTlsBaseUri());
        try {
            homePage.getAnchorByHref("/logout").click();
        }
        catch (ElementNotFoundException e) {
            //Ignore
        }
    }

    @Test
    public void logIn() throws FailingHttpStatusCodeException, MalformedURLException, IOException, InterruptedException {

        HtmlPage page = webClient.getPage(getTlsBaseUri() + "login.jsp");
        HtmlForm form = page.getFormByName("loginform");
        form.<HtmlInput>getInputByName("username").setValueAttribute("root");
        form.<HtmlInput>getInputByName("password").setValueAttribute("secret");
        page = form.<HtmlInput>getInputByName("submit").click();
        // This'll throw an expection if not logged in
        page.getAnchorByHref("/logout");
    }
}
