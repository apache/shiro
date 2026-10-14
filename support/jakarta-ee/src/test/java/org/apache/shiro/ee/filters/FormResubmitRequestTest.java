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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.shiro.ee.filters.FormResubmitSupport.AjaxReplay;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;

import static org.mockito.Mockito.lenient;

import org.mockito.junit.jupiter.MockitoExtension;

/**
 * A full-page replay hides the Faces Ajax header from the target through every accessor
 */
@ExtendWith(MockitoExtension.class)
class FormResubmitRequestTest {
    @Mock
    private HttpServletRequest login;

    @BeforeEach
    void setUp() {
        lenient().when(login.getAttributeNames()).thenReturn(Collections.emptyEnumeration());
        lenient().when(login.getHeaderNames())
                .thenReturn(Collections.enumeration(List.of("Faces-Request", "Host")));
        lenient().when(login.getHeader("Faces-Request")).thenReturn("partial/ajax");
        lenient().when(login.getHeaders("Faces-Request"))
                .thenReturn(Collections.enumeration(List.of("partial/ajax")));
    }

    private FormResubmitRequest request(AjaxReplay ajaxReplay) {
        return new FormResubmitRequest(login, "POST", Map.of(), ajaxReplay);
    }

    @Test
    void facesRequestHeaderIsHiddenFromAllAccessorsOnFullPageReplay() {
        var request = request(AjaxReplay.FULL_PAGE);
        assertThat(request.getHeader("Faces-Request")).isNull();
        assertThat(request.getHeader("faces-request")).isNull();
        assertThat(Collections.list(request.getHeaders("Faces-Request"))).isEmpty();
        assertThat(Collections.list(request.getHeaderNames())).containsExactly("Host");
    }

    @Test
    void facesRequestHeaderIsVisibleOnPassThroughReplay() {
        var request = request(AjaxReplay.PASS_THROUGH);
        assertThat(request.getHeader("Faces-Request")).isEqualTo("partial/ajax");
        assertThat(Collections.list(request.getHeaders("Faces-Request"))).containsExactly("partial/ajax");
        assertThat(Collections.list(request.getHeaderNames())).containsExactly("Faces-Request", "Host");
    }
}
