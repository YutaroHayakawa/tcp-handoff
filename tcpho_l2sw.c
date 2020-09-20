#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#include <tcpho/tcpho_l2sw.h>

int
tcpho_l2sw_add_rule(struct tcpho_l2sw_driver *driver,
		struct tcpho_l2sw_add_attr *attr)
{
	if (driver == NULL || attr == NULL) {
		return EINVAL;
	}

	return driver->add(driver, attr);
}

int
tcpho_l2sw_modify_rule(struct tcpho_l2sw_driver *driver,
		struct tcpho_l2sw_mod_attr *attr)
{
	if (driver == NULL || attr == NULL) {
		return EINVAL;
	}

	return driver->mod(driver, attr);
}

int
tcpho_l2sw_delete_rule(struct tcpho_l2sw_driver *driver,
		struct tcpho_l2sw_del_attr *attr)
{
	if (driver == NULL || attr == NULL) {
		return EINVAL;
	}

	return driver->del(driver, attr);
}
