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
import javax.servlet.http.HttpServletRequest;

import static org.apache.shiro.ee.util.JakartaTransformer.jakartify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
class FormSupportTest {
    @Mock
    private HttpServletRequest request;

    @Test
    void nullReferer() {
        when(request.getHeader("referer")).thenReturn(null);
        assertThat(getReferer(request)).isNull();
    }

    @Test
    void blankReferer() {
        when(request.getHeader("referer")).thenReturn("   ");
        assertThat(getReferer(request)).isNull();
    }

    @Test
    void plainStringReferer() {
        when(request.getHeader("referer")).thenReturn("hello");
        when(request.getContextPath()).thenReturn("/myapp");
        assertThat(getReferer(request)).isNull();
    }

    @Test
    void malformedReferer() {
        when(request.getHeader("referer")).thenReturn("http://exa mple.com");
        assertThat(getReferer(request)).isNull();
    }

    @Test
    void refererWithinContextPath() {
        when(request.getHeader("referer")).thenReturn("https://example.com/myapp/login.xhtml");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isEqualTo("/myapp/login.xhtml");
    }

    @Test
    void refererWithinContextPathWithQuery() {
        when(request.getHeader("referer")).thenReturn("https://example.com/myapp/login.xhtml?a=1&b=2");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isEqualTo("/myapp/login.xhtml?a=1&b=2");
    }

    @Test
    void refererEqualToContextPathBecomesRoot() {
        when(request.getHeader("referer")).thenReturn("https://example.com/myapp");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isEqualTo("/myapp");
    }

    @Test
    void refererOutsideContextPathIsRejected() {
        when(request.getHeader("referer")).thenReturn("https://example.com/otherapp/login.xhtml");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isNull();
    }

    @Test
    void rootContextKeepsPath() {
        when(request.getHeader("referer")).thenReturn("https://example.com/login.xhtml");
        when(request.getContextPath()).thenReturn("");

        assertThat(getReferer(request)).isEqualTo("/login.xhtml");
    }

    @Test
    void rootContextKeepsPathWithQuery() {
        when(request.getHeader("referer")).thenReturn("https://example.com/login.xhtml?x=1");
        when(request.getContextPath()).thenReturn("");

        assertThat(getReferer(request)).isEqualTo("/login.xhtml?x=1");
    }

    @Test
    void normalizedPathWithinContextIsAccepted() {
        when(request.getHeader("referer")).thenReturn("https://example.com/myapp//foo/./bar.xhtml");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isEqualTo("/myapp/foo/bar.xhtml");
    }

    @Test
    void normalizedPathEscapingContextIsRejected() {
        when(request.getHeader("referer")).thenReturn("https://example.com/myapp/../otherapp/page.xhtml");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isNull();
    }

    @Test
    void opaqueUriRefererIsRejected() {
        when(request.getHeader("referer")).thenReturn("mailto:test@example.com");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isNull();
    }

    @Test
    void javascriptUriRefererIsRejected() {
        when(request.getHeader("referer")).thenReturn("javascript:alert(1)");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isNull();
    }

    @Test
    void contextPathPrefixMatchRequiresPathBoundary() {
        when(request.getHeader("referer")).thenReturn("https://example.com/myapplication/page.xhtml");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isNull();
    }

    @Test
    void refererWithFragmentDropsFragmentAndKeepsQueryOnly() {
        when(request.getHeader("referer")).thenReturn("https://example.com/myapp/page.xhtml?a=1#frag");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isEqualTo("/myapp/page.xhtml?a=1");
    }

    @Test
    void externalHostWithMatchingContextCurrentlyPasses() {
        when(request.getHeader("referer")).thenReturn("https://attacker.example/myapp/login.xhtml");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isEqualTo("/myapp/login.xhtml");
    }

    @Test
    void encodedPathTraversalRefererIsRejected() {
        when(request.getHeader("referer"))
                .thenReturn("https://example.com/myapp/%2e%2e/otherapp/page.xhtml");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isNull();
    }

    @Test
    void encodedPathTraversalWithEncodedSlashesRefererIsRejected() {
        when(request.getHeader("referer"))
                .thenReturn("https://example.com/myapp/%2e%2e%2fotherapp%2fpage.xhtml");
        when(request.getContextPath()).thenReturn("/myapp");

        assertThat(getReferer(request)).isNull();
    }

    @Test
    void viewStatePattern() {
        String statefulFormData
                = "j_idt5%3Dj_idt5%26j_idt5%3Aj_idt7%3Daaa%26j_idt5%3Aj_idt9%3Dbbb%26j_idt5%3A"
                + "j_idt11%3DSubmit+...%26" + jakartify("javax.faces.ViewState")
                + "%3D-8335355445345003673%3A-6008443334776649058";
        assertTrue(isJSFStatefulForm(decode(statefulFormData)));
        String statelessFormData
                = "j_idt5%3Dj_idt5%26j_idt5%3Aj_idt7%3Daaa%26j_idt5%3Aj_idt9%3Dbbb%26j_idt5%3A"
                + "j_idt11%3DSubmit+...%26" + jakartify("javax.faces.ViewState") + "%3Dstateless";
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
        assertEquals(jakartify("javax.faces.ViewState=stateless&hello=bye"),
                extractJSFNewViewState("xxx", jakartify("javax.faces.ViewState=stateless&hello=bye")));
        assertEquals(jakartify("javax.faces.ViewState=stateless&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"javax.faces.ViewState\" value=\"123:456\"/>"),
                        jakartify("javax.faces.ViewState=stateless&hello=bye")));
        assertEquals(jakartify("aaa=bbb&javax.faces.ViewState=xxx:yyy&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"javax.faces.ViewState\" value=\"123:456\"/>"),
                        jakartify("aaa=bbb&javax.faces.ViewState=xxx:yyy&hello=bye")));
        assertEquals(jakartify("javax.faces.ViewState=123:456&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"javax.faces.ViewState\" value=\"123:456\"/>"),
                        jakartify("javax.faces.ViewState=987:654&hello=bye")));
        assertEquals(jakartify("javax.faces.ViewState=-123:-456&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"javax.faces.ViewState\" value=\"-123:-456\"/>"),
                        jakartify("javax.faces.ViewState=987:654&hello=bye")));
        assertEquals(jakartify("javax.faces.ViewState=-123:-456&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"javax.faces.ViewState\" value=\"-123:-456\"/>"),
                        jakartify("javax.faces.ViewState=-987:-654&hello=bye")));
        assertEquals(jakartify("aaa=bbb&javax.faces.ViewState=-123:-456&hello=bye"),
                extractJSFNewViewState(jakartify("<input name=\"javax.faces.ViewState\" value=\"-123:-456\"/>"),
                        jakartify("aaa=bbb&javax.faces.ViewState=-987:-654&hello=bye")));
        assertEquals(jakartify("aaa=bbb&javax.faces.ViewState=-123:-456"),
                extractJSFNewViewState(jakartify("<input name=\"javax.faces.ViewState\" value=\"-123:-456\"/>"),
                        jakartify("aaa=bbb&javax.faces.ViewState=-987:-654")));
    }

    @Test
    void noAjaxRequests() {
        assertEquals(
                new PartialAjaxResult(
                        jakartify("aaa=bbb&javax.faces.ViewState=-123:-456&hello=bye"),
                        true, false),
                noJSFAjaxRequests(jakartify("aaa=bbb&javax.faces.ViewState=-123:-456")
                        + jakartify("&javax.faces.partial.ajax=true&hello=bye"), false));
        assertEquals(new PartialAjaxResult("j_idt12=j_idt12&j_idt12:j_idt14=asdf&j_idt12:j_idt16=asdf"
                        + jakartify("&javax.faces.ViewState=7709788254588873136:-8052771455757429917")
                        + "&j_idt12:j_idt18=", true, false),
                noJSFAjaxRequests("j_idt12=j_idt12&j_idt12:j_idt14=asdf&j_idt12:j_idt16=asdf"
                        + jakartify("&javax.faces.ViewState=7709788254588873136:-8052771455757429917")
                        + jakartify("&javax.faces.source=j_idt12:j_idt18")
                        + jakartify("&javax.faces.partial.event=click")
                        + jakartify("&javax.faces.partial.execute=j_idt12:j_idt18 j_idt12")
                        + jakartify("&javax.faces.partial.render=j_idt12")
                        + jakartify("&javax.faces.behavior.event=action")
                        + jakartify("&javax.faces.partial.ajax=false"), false));
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
