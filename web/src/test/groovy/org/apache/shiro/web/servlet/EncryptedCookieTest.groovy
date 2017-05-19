package org.apache.shiro.web.servlet

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.apache.shiro.crypto.CipherService
import static org.easymock.EasyMock.*
import org.apache.shiro.util.ByteSource
import org.easymock.Capture
import org.apache.shiro.codec.Base64

/**
 *
 * @since 1.2.0
 */
class EncryptedCookieTest extends GroovyTestCase {
    def cookieName = "auth"
    def mockHttpRequest
    def mockHttpResponse
    def mockCipherService
    def encryptedValue

    def unencryptedValue = "Hello world"
    def unencryptedValueBytes = unencryptedValue.bytes
    def encryptedValueBase64 = "encryptedcookievalue"
    def encryptedValueBytes = encryptedValueBase64.bytes
    def encryptedValueByteSource
    def key = "key"
    def keyBytes = key.bytes

    def cookie

    void setUp() {
        mockHttpRequest = createMock(HttpServletRequest)
        mockHttpResponse = createMock(HttpServletResponse)
        mockCipherService = createMock(CipherService)
        encryptedValue = createMock(ByteSource)
        encryptedValueByteSource = createMock(ByteSource)

        cookie = new EncryptedCookie(value:unencryptedValue, cipherService:mockCipherService, name:cookieName)
        cookie.setKey(keyBytes)
    }

    void testCreateEncryptedCookie() {
        expect(mockCipherService.encrypt(aryEq(unencryptedValueBytes), aryEq(keyBytes))).andReturn(encryptedValue)
        expect(encryptedValue.toBase64()).andReturn(encryptedValueBase64)
        expect(mockHttpResponse.addHeader(isA(String), isA(String)))

        replay mockHttpRequest, mockHttpResponse, mockCipherService, encryptedValue

        cookie.addCookieHeader(mockHttpResponse, "cookiename", unencryptedValue, "comment", "domain", "path", 1, 1, false, false)

        verify mockHttpRequest, mockHttpResponse, mockCipherService, encryptedValue
    }

    void testReadEncryptedCookie() {
        javax.servlet.http.Cookie mockedCookie = createMock(javax.servlet.http.Cookie)
        javax.servlet.http.Cookie[] mockedCookies = new javax.servlet.http.Cookie[1];
        mockedCookies[0] = mockedCookie

        expect(mockHttpRequest.getCookies()).andReturn(mockedCookies)
        expect(mockCipherService.decrypt(aryEq(Base64.decode(encryptedValueBytes)), aryEq(keyBytes))).andReturn(encryptedValueByteSource)
        expect(encryptedValueByteSource.getBytes()).andReturn(unencryptedValueBytes)
        expect(mockedCookie.getName()).andReturn(cookieName)
        expect(mockedCookie.getValue()).andReturn(encryptedValueBase64)

        replay mockHttpRequest, mockCipherService, encryptedValueByteSource, mockedCookie

        cookie.readValue(mockHttpRequest, mockHttpResponse)

        verify mockHttpRequest, mockCipherService, encryptedValueByteSource, mockedCookie
    }
}
