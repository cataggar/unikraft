/* SPDX-License-Identifier: BSD-3-Clause */
#include <stddef.h>
#include <uk/arch/types.h>

int vmbus_channel_host_nested_ownership_test(void);

int vmbus_control_transmit(const __u8 *message __attribute__((unused)),
			   size_t length __attribute__((unused)))
{
	return 0;
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
	return vmbus_channel_host_nested_ownership_test();
}
