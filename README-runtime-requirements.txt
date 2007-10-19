JSecurity Runtime Requirements
------------------------------

All 3rd party libraries mentioned below are in this distro's lib directory if you don't already have them.

Required jars
-------------
Put jsecurity.jar and Jakarta commons-logging.jar in your application's classpath.

Feature-based dependencies
--------------------------
- If you want to use JSecurity's enterprise session management,
  include ehcache.jar and quartz.jar
  (and if using JDK 1.3 or 1.4, jug.jar & jug-native.zip - not needed for 1.5+)
  
- If you want to use JSecurity's built-in credential (e.g. password) hashing support during 
  authentication (recommended), include Jakarta commons-codec.jar

- If you want to use JSecurity code annotations, include Jakarta commons-beanutils-core.jar