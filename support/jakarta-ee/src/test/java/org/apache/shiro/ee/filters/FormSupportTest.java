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
package org.apache.shiro.ee.filters;

import org.apache.shiro.ee.filters.FormResubmitSupport.PartialAjaxResult;

import static org.apache.shiro.ee.filters.FormResubmitSupport.extractJSFNewViewState;
import static org.apache.shiro.ee.filters.FormResubmitSupport.getReferer;
import static org.apache.shiro.ee.filters.FormResubmitSupport.isJSFStatefulForm;
import static org.apache.shiro.ee.filters.FormResubmitSupport.noJSFAjaxRequests;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.transformCookieHeader;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;

import static org.apache.shiro.ee.util.JakartaTransformer.jakartify;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;

import static org.mockito.Mockito.when;

import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Resubmit forms support
 */
@ExtendWith(MockitoExtension.class)
public class FormSupportTest {
    @Mock
    private HttpServletRequest request;

    @Test
    void nullReferer() {
        when(request.getHeader("referer")).thenReturn(null);
        assertNull(getReferer(request));
    }

    @Test
    void plainStringReferer() {
        when(request.getHeader("referer")).thenReturn("hello");
        assertEquals("hello", getReferer(request));
    }

    @Test
    void switchToHttps() {
        when(request.getHeader("referer")).thenReturn("http://example.com");
        assertEquals("https://example.com", getReferer(request));
    }

    @Test
    void dontSwitchToHttpsWhenCustomPort() {
        when(request.getHeader("referer")).thenReturn("http://example.com:8080/");
        assertEquals("http://example.com:8080/", getReferer(request));
    }

    @Test
    void dontSwitchToHttpsWhenCustomPortNoTrailingSlash() {
        when(request.getHeader("referer")).thenReturn("http://example.com:8080");
        assertEquals("http://example.com:8080", getReferer(request));
    }

    @Test
    void viewStatePattern() {
        String statefulFormData
                = "j_idt5%3Dj_idt5%26j_idt5%3Aj_idt7%3Daaa%26j_idt5%3Aj_idt9%3Dbbb%26j_idt5%3A"
                + "j_idt11%3DSubmit+...%26" + jakartify("jakarta.faces.ViewState")
                + "%3D-8335355445345003673%3A-6008443334776649058";
        assertTrue(isJSFStatefulForm(decode(statefulFormData)));
        String statelessFormData
                = "j_idt5%3Dj_idt5%26j_idt5%3Aj_idt7%3Daaa%26j_idt5%3Aj_idt9%3Dbbb%26j_idt5%3A"
                + "j_idt11%3DSubmit+...%26" + jakartify("jakarta.faces.ViewState") + "%3Dstateless";
        assertFalse(isJSFStatefulForm(statelessFormData));
        assertThrows(NullPointerException.class, () -> isJSFStatefulForm(null));
        String nonJSFFormData
                = "j_idt5%3Dj_idt5%26j_idt5%3Aj_idt7%3Daaa%26j_idt5%3Aj_idt9%3Dbbb%26j_idt5%3A"
                + "j_idt11%3DSubmit+...";
        assertFalse(isJSFStatefulForm("xxx"));
        assertFalse(isJSFStatefulForm(nonJSFFormData));
    }

    @Test
    void extractViewState() {
        assertThrows(NullPointerException.class, () -> extractJSFNewViewState(null, null));
        assertEquals("hello", extractJSFNewViewState("", "hello"));
        assertEquals(jakartify("jakarta.faces.ViewState=stateless&hello=bye"),
                extractJSFNewViewState("xxx", jakartify("jakarta.faces.ViewState=stateless&hello=bye")));
        assertEquals(jakartify("jakarta.faces.ViewState=stateless&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"jakarta.faces.ViewState\" value=\"123:456\"/>"),
                        jakartify("jakarta.faces.ViewState=stateless&hello=bye")));
        assertEquals(jakartify("aaa=bbb&jakarta.faces.ViewState=xxx:yyy&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"jakarta.faces.ViewState\" value=\"123:456\"/>"),
                        jakartify("aaa=bbb&jakarta.faces.ViewState=xxx:yyy&hello=bye")));
        assertEquals(jakartify("jakarta.faces.ViewState=123:456&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"jakarta.faces.ViewState\" value=\"123:456\"/>"),
                        jakartify("jakarta.faces.ViewState=987:654&hello=bye")));
        assertEquals(jakartify("jakarta.faces.ViewState=-123:-456&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"jakarta.faces.ViewState\" value=\"-123:-456\"/>"),
                        jakartify("jakarta.faces.ViewState=987:654&hello=bye")));
        assertEquals(jakartify("jakarta.faces.ViewState=-123:-456&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"jakarta.faces.ViewState\" value=\"-123:-456\"/>"),
                        jakartify("jakarta.faces.ViewState=-987:-654&hello=bye")));
        assertEquals(jakartify("aaa=bbb&jakarta.faces.ViewState=-123:-456&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"jakarta.faces.ViewState\" value=\"-123:-456\"/>"),
                        jakartify("aaa=bbb&jakarta.faces.ViewState=-987:-654&hello=bye")));
        assertEquals(jakartify("aaa=bbb&jakarta.faces.ViewState=-123:-456"),
                extractJSFNewViewState(jakartify("<input name=\"jakarta.faces.ViewState\" value=\"-123:-456\"/>"),
                        jakartify("aaa=bbb&jakarta.faces.ViewState=-987:-654")));
    }

    @Test
    void noAjaxRequests() {
        assertEquals(
                new PartialAjaxResult(
                        jakartify("aaa=bbb&jakarta.faces.ViewState=-123:-456&hello=bye"),
                        true, false),
                noJSFAjaxRequests(jakartify("aaa=bbb&jakarta.faces.ViewState=-123:-456")
                        + jakartify("&jakarta.faces.partial.ajax=true&hello=bye"), false));
        assertEquals(new PartialAjaxResult("j_idt12=j_idt12&j_idt12:j_idt14=asdf&j_idt12:j_idt16=asdf"
                        + jakartify("&jakarta.faces.ViewState=7709788254588873136:-8052771455757429917")
                        + jakartify("&jakarta.faces.source=j_idt12:j_idt18")
                        + jakartify("&jakarta.faces.behavior.event=action"), true, false),
                noJSFAjaxRequests("j_idt12=j_idt12&j_idt12:j_idt14=asdf&j_idt12:j_idt16=asdf"
                        + jakartify("&jakarta.faces.ViewState=7709788254588873136:-8052771455757429917")
                        + jakartify("&jakarta.faces.source=j_idt12:j_idt18")
                        + jakartify("&jakarta.faces.partial.event=click")
                        + jakartify("&jakarta.faces.partial.execute=j_idt12:j_idt18 j_idt12")
                        + jakartify("&jakarta.faces.partial.render=j_idt12")
                        + jakartify("&jakarta.faces.behavior.event=action")
                        + jakartify("&jakarta.faces.partial.ajax=false"), false));
    }

    @Test
    void parseCookies() {
        var map = Map.of("name1", "value1", "name2", "value2", "name3", "value3");
        assertEquals(map, transformCookieHeader(List.of("name1=value1", "name2=value2; path=/my/path", "name3=value3")));
        assertEquals(Map.of("name", ""), transformCookieHeader(List.of("name=")));
        assertEquals(Map.of("JSESSIONID", "abc"),
                transformCookieHeader(List.of("JSESSIONID=\"abc\"; $Version=\"1\"; $Path=\"/mypath\"")));
    }

    private static String decode(String plain) {
        return URLDecoder.decode(plain, StandardCharsets.UTF_8);
    }
}
