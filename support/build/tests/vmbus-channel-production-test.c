/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <stddef.h>
#include <uk/arch/types.h>

int vmbus_channel_host_nested_ownership_test(void);

int vmbus_control_transmit(const __u8 *message __attribute__((unused)),
			   size_t length __attribute__((unused)))
{
	return 0;
}

static unsigned int relid_releases;
static int connection_failed;

int vmbus_channel_host_release_ready(__u32 channel_id);

int vmbus_control_release_relid(__u32 channel_id)
{
	if (channel_id != 1 ||
	    !vmbus_channel_host_release_ready(channel_id))
		return -EINVAL;
	relid_releases++;
	return 0;
}

void vmbus_control_fail(void)
{
	connection_failed = 1;
}

int vmbus_close_message(__u8 *output __attribute__((unused)),
			size_t capacity __attribute__((unused)),
			__u32 channel_id __attribute__((unused)))
{
	return 12;
}

int vmbus_gpadl_teardown_message(__u8 *output __attribute__((unused)),
				 size_t capacity __attribute__((unused)),
				 __u32 channel_id __attribute__((unused)),
				 __u32 gpadl_id __attribute__((unused)))
{
	return 16;
}

int main(void)
{
	int rc = vmbus_channel_host_nested_ownership_test();

	if (rc)
		return rc;
	if (relid_releases != 1 || connection_failed)
		return 20;
	return 0;
}
