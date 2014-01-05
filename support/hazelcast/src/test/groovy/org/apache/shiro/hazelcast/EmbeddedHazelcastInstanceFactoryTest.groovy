package org.apache.shiro.hazelcast

import com.hazelcast.config.Config
import com.hazelcast.core.Hazelcast
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
@PrepareForTest(Hazelcast)
class EmbeddedHazelcastInstanceFactoryTest {

    EmbeddedHazelcastInstanceFactory factory

    @Before
    void setUp() {
        factory = new EmbeddedHazelcastInstanceFactory()
    }

    @Test
    void testNew() {
        assertNotNull factory.config
        assertTrue factory.config instanceof Config
        factory.destroy()
    }

    @Test
    void testGetInstance() {

        mockStatic(Hazelcast)

        def hc = createStrictMock(HazelcastInstance)
        def config = createStrictMock(Config)

        factory.config = config

        //create a mock instead of starting a networked node:
        expect(Hazelcast.newHazelcastInstance(same(config))).andReturn(hc)

        replay Hazelcast, hc, config

        try {
            def instance = factory.getInstance()

            assertNotNull instance
            assertSame instance, hc

        } finally {
            verify Hazelcast, hc, config
        }
    }
}
