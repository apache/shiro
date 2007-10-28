JSecurity Runtime Requirements
------------------------------

All 3rd party libraries mentioned below are in this distro's lib directory if you don't already have them.


Required jars
-------------
Put jsecurity.jar and Jakarta commons-logging.jar in your application's classpath.

JDK 1.3 and 1.4 only: you must include retroweaver.jar and its associated dependendencies
(they can be found in this distro's lib/retroweaver directory).


Feature-based dependencies
--------------------------
- If you want to use JSecurity's enterprise session management:
  . JDK 1.5+: include ehcache.jar and quartz.jar
  . JDK 1.3 or 1.4: include ehcache.jar, quartz.jar, jug.jar and jug-native.zip

- If you want to use JSecurity's built-in credential hashing support (e.g. password hashing) during
  authentication (recommended), include Jakarta commons-codec.jar

- If you want to use JSecurity code annotations, include Jakarta commons-beanutils-core.jar
