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

import static org.apache.shiro.SecurityUtils.getSecurityManager;
import static org.apache.shiro.SecurityUtils.isSecurityManagerTypeOf;
import static org.apache.shiro.SecurityUtils.unwrapSecurityManager;
import static org.apache.shiro.ee.filters.FormAuthenticationFilter.LOGIN_URL_ATTR_NAME;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpHeaderConstants.CONTENT_TYPE;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpHeaderConstants.COOKIE;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpHeaderConstants.LOCATION;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpHeaderConstants.SET_COOKIE;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpResponseCodes.AUTHFAIL;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpResponseCodes.FOUND;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpResponseCodes.OK;
import static org.apache.shiro.ee.filters.FormResubmitSupport.MediaType.APPLICATION_FORM_URLENCODED;
import static org.apache.shiro.ee.filters.FormResubmitSupport.MediaType.TEXT_XML;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.DONT_ADD_ANY_MORE_COOKIES;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.addCookie;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.cookieStreamFromHeader;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.deleteCookie;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.getCookieAge;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.getSessionCookieName;
import java.net.URISyntaxException;
import java.util.Collections;
import org.apache.shiro.ee.filters.Forms.FallbackPredicate;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.transformCookieHeader;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isFormResubmitDisabled;
import java.io.IOException;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import static java.util.function.Predicate.not;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import static javax.faces.application.StateManager.STATE_SAVING_METHOD_CLIENT;
import static javax.faces.application.StateManager.STATE_SAVING_METHOD_PARAM_NAME;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import static org.apache.shiro.ee.util.JakartaTransformer.jakartify;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.util.WebUtils;
import org.jsoup.Jsoup;
import org.jsoup.select.Elements;
import org.omnifaces.util.Faces;
import org.omnifaces.util.Servlets;

/**
 * supporting methods for {@link Forms}
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@SuppressWarnings({"checkstyle:HideUtilityClassConstructor", "checkstyle:MethodCount"})
public class FormResubmitSupport {
    static final String SHIRO_FORM_DATA_KEY = "org.apache.shiro.form-data-key";
    static final String SESSION_EXPIRED_PARAMETER = "org.apache.shiro.sessionExpired";
    static final String FORM_IS_RESUBMITTED = "org.apache.shiro.form-is-resubmitted";
    // encoded view state
    private static final String FACES_VIEW_STATE = jakartify("javax.faces.ViewState");
    private static final String FACES_VIEW_STATE_EQUALS = FACES_VIEW_STATE + "=";
    private static final Pattern VIEW_STATE_PATTERN
            = Pattern.compile(String.format("(.*)(%s[-]?[\\d]+:[-]?[\\d]+)(.*)", FACES_VIEW_STATE_EQUALS));
    private static final String PARTIAL_VIEW = jakartify("javax.faces.partial");
    private static final Pattern PARTIAL_REQUEST_PATTERN
            = Pattern.compile(String.format("[\\&]?%s.\\w+=[\\w\\s:%%\\d]*", PARTIAL_VIEW));
    private static final Pattern INITIAL_AMPERSAND = Pattern.compile("^\\&");
    private static final String FORM_DATA_CACHE = "org.apache.shiro.form-data-cache";
    private static final String FORM_RESUBMIT_HOST = "org.apache.shiro.form-resubmit-host";
    private static final String FORM_RESUBMIT_PORT = "org.apache.shiro.form-resubmit-port";
    private static final Optional<String> RESUBMIT_HOST = Optional.ofNullable(System.getProperty(FORM_RESUBMIT_HOST));
    private static final Optional<Integer> RESUBMIT_PORT = Optional.ofNullable(System.getProperty(FORM_RESUBMIT_PORT))
            .map(Integer::valueOf);

    static class HttpMethod {
        static final String GET = "GET";
        static final String POST = "POST";
    }

    static class HttpHeaderConstants {
        static final String CONTENT_TYPE = "Content-Type";
        static final String LOCATION = "Location";
        static final String COOKIE = "Cookie";
        static final String SET_COOKIE = "Set-Cookie";
    }

    static class MediaType {
        static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
        static final String TEXT_XML = "text/xml";
    }

    static class HttpResponseCodes {
        static final int OK = 200;
        static final int FOUND = 302;
        static final int AUTHFAIL = 401;
    }

    @RequiredArgsConstructor
    @EqualsAndHashCode @ToString
    @SuppressWarnings("VisibilityModifier")
    static class PartialAjaxResult {
        public final String result;
        public final boolean isPartialAjaxRequest;
        public final boolean isStatelessRequest;
    }

    static void savePostDataForResubmit(HttpServletRequest request, HttpServletResponse response, @NonNull String loginUrl) {
        if (isPostRequest(request) && isSecurityManagerTypeOf(getSecurityManager(),
                DefaultSecurityManager.class)) {
            String postData = getPostData(request);
            var cacheKey = UUID.randomUUID();
            DefaultSecurityManager dsm = getSecurityManager(DefaultSecurityManager.class);
            if (dsm.getCacheManager() != null) {
                var cache = dsm.getCacheManager().getCache(FORM_DATA_CACHE);
                var rememberMeManager = (AbstractRememberMeManager) dsm.getRememberMeManager();
                if (rememberMeManager != null && rememberMeManager.getCipherService() != null) {
                    cache.put(cacheKey, rememberMeManager.getCipherService()
                            .encrypt(postData.getBytes(StandardCharsets.UTF_8),
                                    rememberMeManager.getEncryptionCipherKey()).getBytes());
                } else {
                    log.warn("Post-data was saved in plain text due to rememberMeManager not being available");
                    cache.put(cacheKey, postData);
                }
                addCookie(response, request.getServletContext(), SHIRO_FORM_DATA_KEY,
                        cacheKey.toString(), getCookieAge(request, dsm));
            } else {
                log.warn("Shiro Cache manager is not configured, cannot store form data");
            }
        }
        boolean isFacesGetRequest = HttpMethod.GET.equalsIgnoreCase(request.getMethod());
        doFacesRedirect(request, response, request.getContextPath() + loginUrl
                + (isFacesGetRequest ? "" : "?%s=true"), SESSION_EXPIRED_PARAMETER);
    }

    static boolean isPostRequest(ServletRequest request) {
        if (request instanceof HttpServletRequest) {
            return HttpMethod.POST.equalsIgnoreCase(WebUtils.toHttp(request).getMethod());
        } else {
            return false;
        }
    }

    @SneakyThrows(IOException.class)
    static String getPostData(ServletRequest request) {
        return request.getReader().lines().collect(Collectors.joining());
    }

    static String getSavedFormDataFromKey(@NonNull String savedFormDataKey) {
        String savedFormData = null;
        if (isSecurityManagerTypeOf(getSecurityManager(), DefaultSecurityManager.class)) {
            DefaultSecurityManager dsm = getSecurityManager(DefaultSecurityManager.class);
            if (dsm.getCacheManager() != null) {
                var cache = dsm.getCacheManager().getCache(FORM_DATA_CACHE);
                var cacheKey = UUID.fromString(savedFormDataKey);
                var rememberMeManager = (AbstractRememberMeManager) dsm.getRememberMeManager();
                if (rememberMeManager != null && rememberMeManager.getCipherService() != null) {
                    var cachedData = Optional.ofNullable((byte[]) cache.get(cacheKey));
                    savedFormData = cachedData.map(encryptedData ->
                            decrypt(encryptedData, rememberMeManager)).orElse(savedFormData);
                } else {
                    savedFormData = (String) cache.get(cacheKey);
                }
                cache.remove(cacheKey);
            }
        }
        return savedFormData;
    }

    static String decrypt(byte[] encrypted, AbstractRememberMeManager rememberMeManager) {
        return new String(rememberMeManager.getCipherService()
                .decrypt(encrypted, rememberMeManager.getDecryptionCipherKey()).getClonedBytes(),
                StandardCharsets.UTF_8);
    }

    static void saveRequest(HttpServletRequest request, HttpServletResponse response, boolean useReferer) {
        String path = useReferer ? getReferer(request)
                : Servlets.getRequestURLWithQueryString(request);
        if (path != null) {
            Servlets.addResponseCookie(request, response, WebUtils.SAVED_REQUEST_KEY,
                    path, null, request.getContextPath(),
                    // cookie age = session timeout
                    getCookieAge(request, getSecurityManager()));
        }
    }

    static void saveRequestReferer(boolean rv, HttpServletRequest request, HttpServletResponse response) {
        if (rv && HttpMethod.GET.equalsIgnoreCase(request.getMethod())) {
            if (Servlets.getRequestCookie(request, WebUtils.SAVED_REQUEST_KEY) == null) {
                // only save refer when there is no saved request cookie already,
                // and only as a last resort
                saveRequest(request, response, true);
            }
        }
    }

    static String getReferer(HttpServletRequest request) {
        String referer = request.getHeader("referer");
        if (referer != null) {
            // do not switch to https if custom port is specified
            if (!referer.matches("^http:\\/\\/[A-z|.|[0-9]]+:[0-9]+(\\/.*|$)")) {
                referer = referer.replaceFirst("^http:", "https:");
            }
        }
        return referer;
    }

    /**
     * Redirects the user to saved request after login, if available
     * Resubmits the form that caused the logout upon successful login.Form resubmission supports JSF and Ajax forms
     * @param request
     * @param response
     * @param useFallbackPath predicate whether to use fall back path
     * @param fallbackPath
     * @param resubmit if true, attempt to resubmit the form that was unsubmitted prior to logout
     */
    @SneakyThrows({IOException.class, InterruptedException.class})
    static void redirectToSaved(HttpServletRequest request, HttpServletResponse response,
            FallbackPredicate useFallbackPath, String fallbackPath, boolean resubmit) {
        String savedRequest = Servlets.getRequestCookie(request, WebUtils.SAVED_REQUEST_KEY);
        if (savedRequest != null) {
            doRedirectToSaved(request, response, savedRequest, resubmit);
        } else {
            redirectToView(request, response, useFallbackPath, fallbackPath);
        }
    }

    /**
     * redirect to saved request, possibly resubmitting an existing form
     * the saved request is via a cookie
     *
     * @param request
     * @param response
     * @param useFallbackPath
     * @param fallbackPath
     */
    static void redirectToSaved(HttpServletRequest request, HttpServletResponse response,
            FallbackPredicate useFallbackPath, String fallbackPath) {
        redirectToSaved(request, response, useFallbackPath, fallbackPath,
                !isFormResubmitDisabled(request.getServletContext()));
    }


    private static void doRedirectToSaved(HttpServletRequest request, HttpServletResponse response,
            @NonNull String savedRequest, boolean resubmit) throws IOException, InterruptedException {
        deleteCookie(response, request.getServletContext(), WebUtils.SAVED_REQUEST_KEY);
        String savedFormDataKey = Servlets.getRequestCookie(request, SHIRO_FORM_DATA_KEY);
        boolean doRedirectAtEnd = true;
        if (savedFormDataKey != null && resubmit) {
            String formData = getSavedFormDataFromKey(savedFormDataKey);
            if (formData != null) {
                Optional.ofNullable(resubmitSavedForm(formData, savedRequest,
                        request, response, request.getServletContext(), false))
                        .ifPresent(path -> doFacesRedirect(request, response, path));
                doRedirectAtEnd = false;
            } else {
                deleteCookie(response, request.getServletContext(), SHIRO_FORM_DATA_KEY);
            }
        }
        if (doRedirectAtEnd) {
            doFacesRedirect(request, response, savedRequest);
        }
    }

    /**
     * @param request
     * @param response
     */
    static void redirectToView(HttpServletRequest request, HttpServletResponse response) {
        redirectToView(request, response, (path, req) -> false, null);
    }

    /**
     * redirects to current view after a form submit,
     * or the fallback path if predicate succeeds
     *
     * @param request
     * @param response
     * @param useFallbackPath
     * @param fallbackPath
     */
    @SneakyThrows
    static void redirectToView(HttpServletRequest request, HttpServletResponse response,
            FallbackPredicate useFallbackPath, String fallbackPath) {
        boolean useFallback = useFallbackPath.useFallback(request.getRequestURI(), request);
        String referer = getReferer(request);
        String redirectPath = Servlets.getRequestURLWithQueryString(request);
        if (useFallback && referer != null && !isLoginUrl(request)) {
            // the following is used in the logout flow only,
            // because login flow saves the request automatically, without
            // needing a referrer
            useFallback = useFallbackPath.useFallback(referer, request);
            redirectPath = referer;
        }
        if (useFallback) {
            doFacesRedirect(request, response, request.getContextPath() + fallbackPath);
        } else {
            doFacesRedirect(request, response, redirectPath);
        }
    }

    /**
     * flash cookie is preserved here
     *
     * @param request
     * @param response
     * @param path
     * @param paramValues
     */
    private static void doFacesRedirect(HttpServletRequest request, HttpServletResponse response,
            String path, Object... paramValues) {
        if (hasFacesContext()) {
            Faces.redirect(path, paramValues);
        } else {
            Servlets.facesRedirect(request, response, path, paramValues);
        }
    }

    static boolean hasFacesContext() {
        try {
            return Faces.hasContext();
        } catch (Throwable e) {
            return false;
        }
    }

    static boolean isLoginUrl(HttpServletRequest request) {
        String loginUrl = (String) request.getAttribute(LOGIN_URL_ATTR_NAME);
        return loginUrl != null && request.getRequestURI().equals(request.getContextPath() + loginUrl);
    }

    static String resubmitSavedForm(@NonNull String savedFormData, @NonNull String savedRequest,
            HttpServletRequest originalRequest, HttpServletResponse originalResponse,
            ServletContext servletContext, boolean rememberedAjaxResubmit)
            throws InterruptedException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("saved form data: {}", savedFormData);
            log.debug("Set Cookie Headers: {}", originalResponse.getHeaders(SET_COOKIE));
            log.debug("Original Request Headers: {}", Collections.list(originalRequest.getHeaderNames()));
            log.debug("Original Request Cookie Header: {}", Collections.list(originalRequest.getHeaders(COOKIE)));
        }
        if (Boolean.TRUE.toString().equals(originalRequest.getHeader(FORM_IS_RESUBMITTED))) {
            log.debug("Form resubmit: internal auth failure");
            originalResponse.setStatus(AUTHFAIL);
            return resubmitResponseCleanup(originalRequest);
        }
        URI overriddenRequestURI = overrideSavedRequestURI(URI.create(savedRequest));
        HttpClient client = buildHttpClient(overriddenRequestURI, servletContext, originalRequest);
        HttpResponse<String> response;
        PartialAjaxResult decodedFormData;
        try {
            decodedFormData = parseFormData(savedFormData, overriddenRequestURI, client, servletContext);
            HttpRequest postRequest = constructPostRequest(overriddenRequestURI, decodedFormData.result);
            response = sendResubmitRequest(client, postRequest);
        } catch (IOException e) {
            log.warn("Unable to resubmit form to {}" + System.lineSeparator()
                    + "perhaps set org.apache.shiro.form-resubmit-host or "
                    + "org.apache.shiro.form-resubmit-port system property?", overriddenRequestURI, e);
            return savedRequest;
        }
        if (rememberedAjaxResubmit && !decodedFormData.isStatelessRequest) {
            HttpRequest redirectRequest = constructPostRequest(overriddenRequestURI, savedFormData);
            var redirectResponse = client.send(redirectRequest, HttpResponse.BodyHandlers.ofString());
            log.debug("Redirect request: {}, response: {}", redirectRequest, redirectResponse);
            return processResubmitResponse(redirectResponse, originalRequest, originalResponse,
                    response.headers(), savedRequest, servletContext, true, rememberedAjaxResubmit);
        } else {
            deleteCookie(originalResponse, servletContext, SHIRO_FORM_DATA_KEY);
            return processResubmitResponse(response, originalRequest, originalResponse,
                    response.headers(), savedRequest, servletContext,
                    (rememberedAjaxResubmit && decodedFormData.isStatelessRequest) ? false
                            : decodedFormData.isPartialAjaxRequest, rememberedAjaxResubmit);
        }
    }

    @SneakyThrows(URISyntaxException.class)
    private static URI overrideSavedRequestURI(URI savedRequestURI) {
        if (RESUBMIT_HOST.isPresent() || RESUBMIT_PORT.isPresent()) {
            var uri = new URI(savedRequestURI.getScheme(), savedRequestURI.getRawUserInfo(),
                    RESUBMIT_HOST.orElse(savedRequestURI.getHost()), RESUBMIT_PORT.orElse(savedRequestURI.getPort()),
                    savedRequestURI.getRawPath(), savedRequestURI.getRawQuery(), savedRequestURI.getRawFragment());
            log.debug("Form Resubmit - Overriding URI {} with {}", savedRequestURI, uri);
            return uri;
        } else {
            return savedRequestURI;
        }
    }

    private static HttpRequest constructPostRequest(URI request, String body) {
        return HttpRequest.newBuilder().uri(request)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .headers(CONTENT_TYPE, APPLICATION_FORM_URLENCODED,
                        FORM_IS_RESUBMITTED, Boolean.TRUE.toString())
                .build();
    }

    private static HttpResponse<String>
    sendResubmitRequest(HttpClient client, HttpRequest request) throws IOException, InterruptedException {
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (log.isDebugEnabled()) {
            log.debug("Resubmit request: {}, response: {}", request, response);
            log.debug("Response Headers: {}", response.headers().map());
        }
        if (response.statusCode() == AUTHFAIL) {
            log.debug("processing authfail");
            var cookieManager = (CookieManager) client.cookieHandler().get();
            cookieStreamFromHeader(response.headers().allValues(SET_COOKIE))
                    .forEach(cookie -> cookieManager.getCookieStore().add(request.uri(), cookie));
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (log.isDebugEnabled()) {
                log.debug("Resubmit request(authfail): {}, response: {}", request, response);
                log.debug("Response Headers(authfail): {}", response.headers().map());
            }
        }
        return response;
    }

    private static PartialAjaxResult parseFormData(String savedFormData, URI savedRequest,
            HttpClient client, ServletContext servletContext) throws IOException, InterruptedException {
        boolean isStateless = true;
        if (!isJSFClientStateSavingMethod(servletContext)) {
            String decodedFormData = URLDecoder.decode(savedFormData, StandardCharsets.UTF_8);
            if (isJSFStatefulForm(decodedFormData)) {
                isStateless = false;
                savedFormData = getJSFNewViewState(savedRequest, client, decodedFormData);
            }
        }
        return noJSFAjaxRequests(savedFormData, isStateless);
    }

    @SuppressWarnings("fallthrough")
    private static String processResubmitResponse(HttpResponse<String> response,
            HttpServletRequest originalRequest, HttpServletResponse originalResponse,
            HttpHeaders headers, String savedRequest, ServletContext servletContext,
            boolean isPartialAjaxRequest, boolean rememberedAjaxResubmit) throws IOException {
        switch (response.statusCode()) {
            case FOUND:
                if (rememberedAjaxResubmit) {
                    originalResponse.setStatus(OK);
                } else {
                    // can't use Faces.redirect() here
                    originalResponse.setStatus(response.statusCode());
                    originalResponse.setHeader(LOCATION, response.headers().firstValue(LOCATION).orElseThrow());
                }
            case OK:
                // do not duplicate the session cookie(s)
                transformCookieHeader(headers.allValues(SET_COOKIE))
                        .entrySet().stream().filter(not(entry -> entry.getKey()
                                .startsWith(getSessionCookieName(servletContext, getSecurityManager()))))
                        .forEach(entry -> addCookie(originalResponse, servletContext,
                                entry.getKey(), entry.getValue(), -1));
                if (isPartialAjaxRequest) {
                    originalResponse.setHeader(CONTENT_TYPE, TEXT_XML);
                    originalResponse.setCharacterEncoding(StandardCharsets.UTF_8.name());
                    originalResponse.getWriter().append(String.format(
                            "<partial-response><redirect url=\"%s\"></redirect></partial-response>",
                            savedRequest));
                } else {
                    originalResponse.getWriter().append(response.body());
                }
                return resubmitResponseCleanup(originalRequest);
            default:
                return savedRequest;
        }
    }

    private static String resubmitResponseCleanup(HttpServletRequest originalRequest) {
        originalRequest.setAttribute(DONT_ADD_ANY_MORE_COOKIES, Boolean.TRUE);
        if (hasFacesContext()) {
            Faces.responseComplete();
        }
        return null;
    }

    private static HttpClient buildHttpClient(URI savedRequest, ServletContext servletContext,
            HttpServletRequest originalRequest) {
        CookieManager cookieManager = new CookieManager();
        var session = SecurityUtils.getSubject().getSession();
        var sessionCookieName = getSessionCookieName(servletContext, getSecurityManager());
        var sessionCookie = new HttpCookie(sessionCookieName, session.getId().toString());
        sessionCookie.setPath(servletContext.getContextPath());
        sessionCookie.setVersion(0);
        cookieManager.getCookieStore().add(savedRequest, sessionCookie);
        log.debug("Setting Cookie {}", sessionCookieName);
        for (Cookie origCookie : originalRequest.getCookies()) {
            if (!origCookie.getName().equals(sessionCookieName)) {
                try {
                    log.debug("Setting Cookie {}", origCookie.getName());
                    HttpCookie cookie = new HttpCookie(origCookie.getName(), origCookie.getValue());
                    cookie.setPath(servletContext.getContextPath());
                    cookie.setVersion(0);
                    cookieManager.getCookieStore().add(savedRequest, cookie);
                } catch (IllegalArgumentException e) {
                    log.warn("Form Resubmit: Ignoring invalid cookie [{} - {}]",
                            origCookie.getName(), origCookie.getValue(), e);
                }
            }
        }
        return HttpClient.newBuilder().cookieHandler(cookieManager).build();
    }

    public static DefaultWebSessionManager getNativeSessionManager(SecurityManager securityManager) {
        DefaultWebSessionManager rv = null;
        SecurityManager unwrapped = unwrapSecurityManager(securityManager, SecurityManager.class, type -> false);
        if (unwrapped instanceof SessionsSecurityManager) {
            var ssm = (SessionsSecurityManager) unwrapped;
            var sm = ssm.getSessionManager();
            if (sm instanceof DefaultWebSessionManager) {
                rv = (DefaultWebSessionManager) sm;
            }
        }
        return rv;
    }

    private static String getJSFNewViewState(URI savedRequest, HttpClient client, String savedFormData)
            throws IOException, InterruptedException {
        var getRequest = HttpRequest.newBuilder().uri(savedRequest).GET().build();
        HttpResponse<String> htmlResponse = sendResubmitRequest(client, getRequest);
        if (htmlResponse.statusCode() == OK) {
            savedFormData = extractJSFNewViewState(htmlResponse.body(), savedFormData);
        }
        return savedFormData;
    }

    static String extractJSFNewViewState(@NonNull String responseBody, @NonNull String savedFormData) {
        Elements elts = Jsoup.parse(responseBody).select(String.format("input[name=%s]", FACES_VIEW_STATE));
        if (!elts.isEmpty()) {
            String viewState = elts.first().attr("value");

            var matcher = VIEW_STATE_PATTERN.matcher(savedFormData);
            if (matcher.matches()) {
                savedFormData = matcher.replaceFirst(String.format("$1%s%s$3",
                        FACES_VIEW_STATE_EQUALS, viewState));
                log.debug("Encoded w/Replaced ViewState: {}", savedFormData);
            }
        }
        return savedFormData;
    }

    static PartialAjaxResult noJSFAjaxRequests(String savedFormData, boolean isStateless) {
        var partialMatcher = PARTIAL_REQUEST_PATTERN.matcher(savedFormData);
        boolean hasPartialAjax = partialMatcher.find();
        return new PartialAjaxResult(isStateless ? savedFormData : INITIAL_AMPERSAND.matcher(partialMatcher
                .replaceAll("")).replaceFirst(""), hasPartialAjax, isStateless);
    }

    static boolean isJSFStatefulForm(@NonNull String savedFormData) {
        var matcher = VIEW_STATE_PATTERN.matcher(savedFormData);
        return matcher.find() && matcher.groupCount() >= 2
                && !matcher.group(2).equalsIgnoreCase("stateless");
    }

    static boolean isJSFClientStateSavingMethod(ServletContext servletContext) {
        return STATE_SAVING_METHOD_CLIENT.equals(
                servletContext.getInitParameter(STATE_SAVING_METHOD_PARAM_NAME));
    }
}
