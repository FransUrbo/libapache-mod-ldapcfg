diff -urN build-tree.orig/mod_ldap_cfg/mod_ldap_cfg.c build-tree/mod_ldap_cfg/mod_ldap_cfg.c
--- build-tree.orig/mod_ldap_cfg/mod_ldap_cfg.c	Fri Sep  2 05:07:25 2005
+++ build-tree/mod_ldap_cfg/mod_ldap_cfg.c	Fri Sep  2 05:07:36 2005
@@ -16,7 +16,7 @@
 // LDAP #includes
 
 #include <ldap.h>
-#include <sasl.h>
+#include <sasl/sasl.h>
 
 // Apache #includes
 
