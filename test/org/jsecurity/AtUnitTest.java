package org.jsecurity;

import atunit.AtUnit;
import atunit.Container;
import atunit.MockFramework;
import org.junit.runner.RunWith;

/**
 * Super class that simply provides boiler plate annotations for subclass tests.
 */
@RunWith(AtUnit.class)
@Container(Container.Option.SPRING)
@MockFramework(MockFramework.Option.EASYMOCK)
public class AtUnitTest {}
