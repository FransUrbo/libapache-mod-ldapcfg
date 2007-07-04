all: mod_ldap_cfg.so

mod_ldap_cfg.so: mod_ldap_cfg.c
	apxs -c -Wc,-g -i -l ldap mod_ldap_cfg.c

clean:
	rm -rf *.o *.so
