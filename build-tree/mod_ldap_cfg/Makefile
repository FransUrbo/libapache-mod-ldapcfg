APXS := $(shell if ! which apxs; then which apxs2; fi)

all: mod_ldap_cfg.o

mod_ldap_cfg.o: mod_ldap_cfg.c
	$(APXS) -c -Wc,-g -l ldap mod_ldap_cfg.c

clean:
	rm -rf *.o *.so *.lo *.la *.slo *~ .libs

install:
	$(APXS) -i mod_ldap_cfg.la

.PHONY: all clean install
