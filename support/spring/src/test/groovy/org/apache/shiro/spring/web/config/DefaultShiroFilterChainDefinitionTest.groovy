package org.apache.shiro.spring.web.config

import org.junit.Test

import static org.junit.Assert.assertEquals

/**
 * Tests for {@link DefaultShiroFilterChainDefinition}.
 */
class DefaultShiroFilterChainDefinitionTest {

    @Test
    void insertOrderTest() {

        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition()
        chainDefinition.addPathDefinition("z", "def")
        chainDefinition.addPathDefinition("c", "def")
        chainDefinition.addPathDefinition("b", "def")
        chainDefinition.addPathDefinition("a", "def")

        Iterator<String> resultKeysInOrder = chainDefinition.getFilterChainMap().keySet().iterator()

        assertEquals "z", resultKeysInOrder.next()
        assertEquals "c", resultKeysInOrder.next()
        assertEquals "b", resultKeysInOrder.next()
        assertEquals "a", resultKeysInOrder.next()
    }

}
