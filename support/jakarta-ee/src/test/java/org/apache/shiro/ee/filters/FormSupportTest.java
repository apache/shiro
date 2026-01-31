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

import static org.apache.shiro.ee.filters.FormResubmitSupport.FACES_SOURCE_PATTERN;
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
class FormSupportTest {
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
                        + "&jakarta.faces.ViewState=7709788254588873136:-8052771455757429917&j_idt12:j_idt18=",
                        true, false));
    }

    @Test
    void parseFacesSources() {
        var matcher = FACES_SOURCE_PATTERN.matcher("j_idt12=j_idt12&j_idt12:j_idt14=asdf&j_idt12:j_idt16=asdf"
                + "&jakarta.faces.ViewState=7709788254588873136:-8052771455757429917"
                + "&jakarta.faces.source=j_idt12:j_idt18"
                + "&jakarta.faces.partial.event=click"
                + "&jakarta.faces.partial.execute=j_idt12:j_idt18 j_idt12"
                + "&jakarta.faces.partial.render=j_idt12"
                + "&jakarta.faces.behavior.event=action"
                + "&jakarta.faces.partial.ajax=false");
        assertThat(matcher.find()).isTrue();
        assertThat(matcher.group(1)).isEqualTo("j_idt12:j_idt18");
    }

    @Test
    void clientSideStateSavingNoAjax() {
        String savedRequest = """
                secondForm=secondForm&secondForm:address=asfd&secondForm:city=asdf
                &jakarta.faces.ViewState=5BDAqkysYaMvzcnTG3bVSXRoK43OvdMyb8w6RicBatqzOdHBwl/cFvOXYfYCwvJoBU6/qv
                735kadAP67luQ/wMqF4jAQyBKDdxy5F4CxNz4FhAYC2iCd613QnwLWP8BX3so7BylQxIN2Y64n6LUogwkgZLEAHgTBDQGwG
                F2SMhdkehYjYo5/IwRP2rrlE0DAWU7gYMeqRFutzwi7wJ5pBYc9zxA3D/TzJofi8ssR3vED2b3y5Xz8nLLgzK7Zz2Kf4YDQ
                BoiX/FLoL+qeNY7ooL+2/kphH1RuxqcFVM9izcq5Egqk0m7DvN5LB6a6JRH+yEgmBhi1Ns4k89FFcrSfu8pyD4gk8ZVMvQL
                P2dRSBSMW3/ECkrbQelN5NyRKls9cdU8htkxYTfJmceLQGcw7FlU63KJFOkUCk+QUzQzjJL90RJ/nu/Efpq/U6tIsSZJVAO
                8xyQaqoV38Q/5PVdvl23zapm/WlbtDDOuKoE5ToXCh2s43Gf8VIK+dXkwTLsgsbgt4GrTSHdT9GYA7aE8TDC/gTqDhbkLM7
                QjIdmCT7ELQVplSKOoQg5YPRPpAAswyxsFHtuwE7k9sLzORp0GhPfehryKEHJDL4AZJA1jTdTDZAKl3qU1bvp4kBOE5STj5
                s1cDihxs+hWgEuuZsN0CDP06AUBlHE6ALmE52oH9CL4N+pAiUy3mlbVloM83+pfIyC4h3b8AnvDdlw788NiFA3mgsQQTX2v
                lbAemEX2+50CobUjfx3bVo+jWBEyaAGJmWLFA6Jo4MD8xFeIST7Q/kME+GMtlR1ePE3E9a7jCb3Nt3dPLotjWGpSUg4n7Y+
                5uvxdvth9U0PQF8G0+so1MAWTrmCTZS1c15xuAk/lfOsP9viwls6UdfdA1nhzypizwUuIgsHKwxz92j+RXs9fz1uaQdldcC
                O51Rj2eMsIHdls+sz6XsXcSfJq2k8OJMBMHqAW4fu4lVoKhL6uLupvMgqdM7gF777/9ejg7RuFdT4lYpVYnSYFprCBUSz/q
                Vbz4b2Rre7zhBzUIxfa2KNHgWhIFD94M+zZI1mbXfN7OtcjPHY9pCxP1jinmlLrPcR9rjXZgSbOtyQSHFyj9VN3ry2ySMj7
                +pPVPIhNPE8PoYj9psBzneUQJJLrSJN1d7aW+
                &jakarta.faces.source=secondForm:submitSecond
                &jakarta.faces.partial.event=click
                &jakarta.faces.partial.execute=secondForm:submitSecond secondForm
                &jakarta.faces.partial.render=secondForm&jakarta.faces.behavior.event=action
                &jakarta.faces.partial.ajax=true""".replace("\n", "");
        assertThat(noJSFAjaxRequests(savedRequest, true).result).isEqualTo("""
                secondForm=secondForm&secondForm:address=asfd&secondForm:city=asdf
                &jakarta.faces.ViewState=5BDAqkysYaMvzcnTG3bVSXRoK43OvdMyb8w6RicBatqzOdHBwl/cFvOXYfYCwvJoBU6/qv
                735kadAP67luQ/wMqF4jAQyBKDdxy5F4CxNz4FhAYC2iCd613QnwLWP8BX3so7BylQxIN2Y64n6LUogwkgZLEAHgTBDQGwG
                F2SMhdkehYjYo5/IwRP2rrlE0DAWU7gYMeqRFutzwi7wJ5pBYc9zxA3D/TzJofi8ssR3vED2b3y5Xz8nLLgzK7Zz2Kf4YDQ
                BoiX/FLoL+qeNY7ooL+2/kphH1RuxqcFVM9izcq5Egqk0m7DvN5LB6a6JRH+yEgmBhi1Ns4k89FFcrSfu8pyD4gk8ZVMvQL
                P2dRSBSMW3/ECkrbQelN5NyRKls9cdU8htkxYTfJmceLQGcw7FlU63KJFOkUCk+QUzQzjJL90RJ/nu/Efpq/U6tIsSZJVAO
                8xyQaqoV38Q/5PVdvl23zapm/WlbtDDOuKoE5ToXCh2s43Gf8VIK+dXkwTLsgsbgt4GrTSHdT9GYA7aE8TDC/gTqDhbkLM7
                QjIdmCT7ELQVplSKOoQg5YPRPpAAswyxsFHtuwE7k9sLzORp0GhPfehryKEHJDL4AZJA1jTdTDZAKl3qU1bvp4kBOE5STj5
                s1cDihxs+hWgEuuZsN0CDP06AUBlHE6ALmE52oH9CL4N+pAiUy3mlbVloM83+pfIyC4h3b8AnvDdlw788NiFA3mgsQQTX2v
                lbAemEX2+50CobUjfx3bVo+jWBEyaAGJmWLFA6Jo4MD8xFeIST7Q/kME+GMtlR1ePE3E9a7jCb3Nt3dPLotjWGpSUg4n7Y+
                5uvxdvth9U0PQF8G0+so1MAWTrmCTZS1c15xuAk/lfOsP9viwls6UdfdA1nhzypizwUuIgsHKwxz92j+RXs9fz1uaQdldcC
                O51Rj2eMsIHdls+sz6XsXcSfJq2k8OJMBMHqAW4fu4lVoKhL6uLupvMgqdM7gF777/9ejg7RuFdT4lYpVYnSYFprCBUSz/q
                Vbz4b2Rre7zhBzUIxfa2KNHgWhIFD94M+zZI1mbXfN7OtcjPHY9pCxP1jinmlLrPcR9rjXZgSbOtyQSHFyj9VN3ry2ySMj7
                +pPVPIhNPE8PoYj9psBzneUQJJLrSJN1d7aW+
                &jakarta.faces.source=secondForm:submitSecond
                &jakarta.faces.partial.event=click
                &jakarta.faces.partial.execute=secondForm:submitSecond secondForm
                &jakarta.faces.partial.render=secondForm&jakarta.faces.behavior.event=action
                &jakarta.faces.partial.ajax=true&secondForm:submitSecond=""".replace("\n", ""));
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
