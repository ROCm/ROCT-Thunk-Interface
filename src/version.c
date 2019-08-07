/*
 * Copyright © 2014 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including
 * the next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "libhsakmt.h"
#include <stdlib.h>
#include <string.h>
#include <linux/kfd_ioctl.h>

HSAKMT_STATUS HSAKMTAPI hsaKmtGetVersion(HsaVersionInfo *VersionInfo)
{
	CHECK_KFD_OPEN();

	struct kfd_ioctl_get_version_args args = {0};

	if (kmtIoctl(kfd_fd, AMDKFD_IOC_GET_VERSION, &args) == -1)
		return HSAKMT_STATUS_ERROR;

	VersionInfo->KernelInterfaceMajorVersion = args.major_version;
	VersionInfo->KernelInterfaceMinorVersion = args.minor_version;

	return HSAKMT_STATUS_SUCCESS;
}
