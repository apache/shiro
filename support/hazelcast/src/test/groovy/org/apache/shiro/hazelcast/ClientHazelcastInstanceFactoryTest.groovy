package org.apache.shiro.hazelcast

import com.hazelcast.client.HazelcastClient
import com.hazelcast.client.config.ClientConfig
import com.hazelcast.core.HazelcastInstance
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.same
import static org.junit.Assert.*
import static org.powermock.api.easymock.PowerMock.*

@RunWith(PowerMockRunner)
@PrepareForTest(HazelcastClient)
class ClientHazelcastInstanceFactoryTest {

    ClientHazelcastInstanceFactory factory

    @Before
    void setUp() {
        factory = new ClientHazelcastInstanceFactory()
    }

    @Test
    void testNew() {
        assertNotNull factory.config
        assertTrue factory.config instanceof ClientConfig
        factory.destroy()
    }

    @Test
    void testGetInstance() {

        mockStatic(HazelcastClient)

        def hc = createStrictMock(HazelcastInstance)
        def config = createStrictMock(ClientConfig)

        factory.config = config

        //create a mock instead of starting a networked node:
        expect(HazelcastClient.newHazelcastClient(same(config))).andReturn(hc)

        replay HazelcastClient, hc, config

        try {
            def instance = factory.getInstance()

            assertNotNull instance
            assertSame instance, hc

        } finally {
            verify HazelcastClient, hc, config
        }
    }
}
