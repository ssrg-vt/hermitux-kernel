#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <asm/uhyve.h>
#include <hermit/minifs.h>

int sys_sync(void) {

	if(minifs_enabled)
		return 0;

	uhyve_send(UHYVE_PORT_SYNC, 0x0);
	return 0;
}
