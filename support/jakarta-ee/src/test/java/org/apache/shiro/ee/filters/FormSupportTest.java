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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

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
        assertThat(getReferer(request)).isNull();
    }

    @Test
    void plainStringReferer() {
        when(request.getHeader("referer")).thenReturn("hello");
        assertThat(getReferer(request)).isEqualTo("hello");
    }

    @Test
    void switchToHttps() {
        when(request.getHeader("referer")).thenReturn("http://example.com");
        assertThat(getReferer(request)).isEqualTo("https://example.com");
    }

    @Test
    void dontSwitchToHttpsWhenCustomPort() {
        when(request.getHeader("referer")).thenReturn("http://example.com:8080/");
        assertThat(getReferer(request)).isEqualTo("http://example.com:8080/");
    }

    @Test
    void dontSwitchToHttpsWhenCustomPortNoTrailingSlash() {
        when(request.getHeader("referer")).thenReturn("http://example.com:8080");
        assertThat(getReferer(request)).isEqualTo("http://example.com:8080");
    }

    @Test
    void viewStatePattern() {
        String statefulFormData
                = "j_idt5%3Dj_idt5%26j_idt5%3Aj_idt7%3Daaa%26j_idt5%3Aj_idt9%3Dbbb%26j_idt5%3A"
                + "j_idt11%3DSubmit+...%26jakarta.faces.ViewState"
                + "%3D-8335355445345003673%3A-6008443334776649058";
        assertThat(isJSFStatefulForm(decode(statefulFormData))).isTrue();
        String statelessFormData
                = "j_idt5%3Dj_idt5%26j_idt5%3Aj_idt7%3Daaa%26j_idt5%3Aj_idt9%3Dbbb%26j_idt5%3A"
                + "j_idt11%3DSubmit+...%26jakarta.faces.ViewState%3Dstateless";
        assertThat(isJSFStatefulForm(statelessFormData)).isFalse();
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> isJSFStatefulForm(null));
        String nonJSFFormData
                = "j_idt5%3Dj_idt5%26j_idt5%3Aj_idt7%3Daaa%26j_idt5%3Aj_idt9%3Dbbb%26j_idt5%3A"
                + "j_idt11%3DSubmit+...";
        assertThat(isJSFStatefulForm("xxx")).isFalse();
        assertThat(isJSFStatefulForm(nonJSFFormData)).isFalse();
    }

    @Test
    void extractViewState() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> extractJSFNewViewState(null, null));
        assertThat(extractJSFNewViewState("", "hello")).isEqualTo("hello");
        assertThat(extractJSFNewViewState("xxx", "jakarta.faces.ViewState=stateless&hello=bye"))
                .isEqualTo("jakarta.faces.ViewState=stateless&hello=bye");
        assertThat(extractJSFNewViewState("<input name=\"jakarta.faces.ViewState\" value=\"123:456\"/>",
                        "jakarta.faces.ViewState=stateless&hello=bye"))
                .isEqualTo("jakarta.faces.ViewState=stateless&hello=bye");
        assertThat(extractJSFNewViewState("<input name=\"jakarta.faces.ViewState\" value=\"123:456\"/>",
                        "aaa=bbb&jakarta.faces.ViewState=xxx:yyy&hello=bye"))
                .isEqualTo("aaa=bbb&jakarta.faces.ViewState=xxx:yyy&hello=bye");
        assertThat(extractJSFNewViewState("<input name=\"jakarta.faces.ViewState\" value=\"123:456\"/>",
                        "jakarta.faces.ViewState=987:654&hello=bye"))
                .isEqualTo("jakarta.faces.ViewState=123:456&hello=bye");
        assertThat(extractJSFNewViewState("<input name=\"jakarta.faces.ViewState\" value=\"-123:-456\"/>",
                        "jakarta.faces.ViewState=987:654&hello=bye"))
                .isEqualTo("jakarta.faces.ViewState=-123:-456&hello=bye");
        assertThat(extractJSFNewViewState("<input name=\"jakarta.faces.ViewState\" value=\"-123:-456\"/>",
                        "jakarta.faces.ViewState=-987:-654&hello=bye"))
                .isEqualTo("jakarta.faces.ViewState=-123:-456&hello=bye");
        assertThat(extractJSFNewViewState("<input name=\"jakarta.faces.ViewState\" value=\"-123:-456\"/>",
                        "aaa=bbb&jakarta.faces.ViewState=-987:-654&hello=bye"))
                .isEqualTo("aaa=bbb&jakarta.faces.ViewState=-123:-456&hello=bye");
        assertThat(extractJSFNewViewState("<input name=\"jakarta.faces.ViewState\" value=\"-123:-456\"/>",
                        "aaa=bbb&jakarta.faces.ViewState=-987:-654"))
                .isEqualTo("aaa=bbb&jakarta.faces.ViewState=-123:-456");
    }

    @Test
    void noAjaxRequests() {
        assertThat(noJSFAjaxRequests("aaa=bbb&jakarta.faces.ViewState=-123:-456"
                        + "&jakarta.faces.partial.ajax=true&hello=bye", false)).isEqualTo(new PartialAjaxResult(
                        "aaa=bbb&jakarta.faces.ViewState=-123:-456&hello=bye",
                        true, false));
        assertThat(noJSFAjaxRequests("j_idt12=j_idt12&j_idt12:j_idt14=asdf&j_idt12:j_idt16=asdf"
                        + "&jakarta.faces.ViewState=7709788254588873136:-8052771455757429917"
                        + "&jakarta.faces.source=j_idt12:j_idt18"
                        + "&jakarta.faces.partial.event=click"
                        + "&jakarta.faces.partial.execute=j_idt12:j_idt18 j_idt12"
                        + "&jakarta.faces.partial.render=j_idt12"
                        + "&jakarta.faces.behavior.event=action"
                        + "&jakarta.faces.partial.ajax=false", false))
                .isEqualTo(new PartialAjaxResult("j_idt12=j_idt12&j_idt12:j_idt14=asdf&j_idt12:j_idt16=asdf"
                        + "&jakarta.faces.ViewState=7709788254588873136:-8052771455757429917"
                        + "&jakarta.faces.source=j_idt12:j_idt18"
                        + "&jakarta.faces.behavior.event=action", true, false));
    }

    @Test
    void parseCookies() {
        var map = Map.of("name1", "value1", "name2", "value2", "name3", "value3");
        assertThat(transformCookieHeader(List.of("name1=value1", "name2=value2; path=/my/path", "name3=value3"))).isEqualTo(map);
        assertThat(transformCookieHeader(List.of("name="))).isEqualTo(Map.of("name", ""));
        assertThat(transformCookieHeader(List.of("JSESSIONID=\"abc\"; $Version=\"1\"; $Path=\"/mypath\"")))
            .isEqualTo(Map.of("JSESSIONID", "abc"));
    }

    private static String decode(String plain) {
        return URLDecoder.decode(plain, StandardCharsets.UTF_8);
    }
}
