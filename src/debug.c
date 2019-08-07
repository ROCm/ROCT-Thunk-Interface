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
#include <linux/kfd_ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool *is_device_debugged;
int debug_get_reg_status(uint32_t node_id, bool *is_debugged);

HSAKMT_STATUS init_device_debugging_memory(unsigned int NumNodes)
{
	unsigned int i;

	is_device_debugged = malloc(NumNodes * sizeof(bool));
	if (!is_device_debugged)
		return HSAKMT_STATUS_NO_MEMORY;

	for (i = 0; i < NumNodes; i++)
		is_device_debugged[i] = false;

	return HSAKMT_STATUS_SUCCESS;
}

void destroy_device_debugging_memory(void)
{
	if (is_device_debugged) {
		free(is_device_debugged);
		is_device_debugged = NULL;
	}
}

HSAKMT_STATUS HSAKMTAPI hsaKmtDbgRegister(HSAuint32 NodeId)
{
	HSAKMT_STATUS result;
	uint32_t gpu_id;

	CHECK_KFD_OPEN();

	if (!is_device_debugged)
		return HSAKMT_STATUS_NO_MEMORY;

	result = validate_nodeid(NodeId, &gpu_id);
	if (result != HSAKMT_STATUS_SUCCESS)
		return result;

	struct kfd_ioctl_dbg_register_args args = {0};

	args.gpu_id = gpu_id;

	long err = kmtIoctl(kfd_fd, AMDKFD_IOC_DBG_REGISTER, &args);

	if (err == 0)
		result = HSAKMT_STATUS_SUCCESS;
	else
		result = HSAKMT_STATUS_ERROR;

	return result;
}

HSAKMT_STATUS HSAKMTAPI hsaKmtDbgUnregister(HSAuint32 NodeId)
{
	uint32_t gpu_id;
	HSAKMT_STATUS result;

	CHECK_KFD_OPEN();

	if (!is_device_debugged)
		return HSAKMT_STATUS_NO_MEMORY;

	result = validate_nodeid(NodeId, &gpu_id);
	if (result != HSAKMT_STATUS_SUCCESS)
		return result;

	struct kfd_ioctl_dbg_unregister_args args = {0};

	args.gpu_id = gpu_id;
	long err = kmtIoctl(kfd_fd, AMDKFD_IOC_DBG_UNREGISTER, &args);

	if (err)
		return HSAKMT_STATUS_ERROR;

	return HSAKMT_STATUS_SUCCESS;
}

HSAKMT_STATUS HSAKMTAPI hsaKmtDbgWavefrontControl(HSAuint32 NodeId,
						  HSA_DBG_WAVEOP Operand,
						  HSA_DBG_WAVEMODE Mode,
						  HSAuint32 TrapId,
						  HsaDbgWaveMessage *DbgWaveMsgRing)
{
	HSAKMT_STATUS result;
	uint32_t gpu_id;

	struct kfd_ioctl_dbg_wave_control_args *args;

	CHECK_KFD_OPEN();

	result = validate_nodeid(NodeId, &gpu_id);
	if (result != HSAKMT_STATUS_SUCCESS)
		return result;


/* Determine Size of the ioctl buffer */
	uint32_t buff_size = sizeof(Operand) + sizeof(Mode) + sizeof(TrapId) +
			     sizeof(DbgWaveMsgRing->DbgWaveMsg) +
			     sizeof(DbgWaveMsgRing->MemoryVA) + sizeof(*args);

	args = (struct kfd_ioctl_dbg_wave_control_args *)malloc(buff_size);
	if (!args)
		return HSAKMT_STATUS_ERROR;

	memset(args, 0, buff_size);

	args->gpu_id = gpu_id;
	args->buf_size_in_bytes = buff_size;

	/* increment pointer to the start of the non fixed part */
	unsigned char *run_ptr = (unsigned char *)args + sizeof(*args);

	/* save variable content pointer for kfd */
	args->content_ptr = (uint64_t)run_ptr;

	/* insert items, and increment pointer accordingly */
	*((HSA_DBG_WAVEOP *)run_ptr) = Operand;
	run_ptr += sizeof(Operand);

	*((HSA_DBG_WAVEMODE *)run_ptr) = Mode;
	run_ptr += sizeof(Mode);

	*((HSAuint32 *)run_ptr) = TrapId;
	run_ptr += sizeof(TrapId);

	*((HsaDbgWaveMessageAMD *)run_ptr) = DbgWaveMsgRing->DbgWaveMsg;
	run_ptr += sizeof(DbgWaveMsgRing->DbgWaveMsg);

	*((void **)run_ptr) = DbgWaveMsgRing->MemoryVA;
	run_ptr += sizeof(DbgWaveMsgRing->MemoryVA);

	/* send to kernel */
	long err = kmtIoctl(kfd_fd, AMDKFD_IOC_DBG_WAVE_CONTROL, args);

	free(args);

	if (err)
		return HSAKMT_STATUS_ERROR;

	return HSAKMT_STATUS_SUCCESS;
}

HSAKMT_STATUS HSAKMTAPI hsaKmtDbgAddressWatch(HSAuint32 NodeId,
					      HSAuint32 NumWatchPoints,
					      HSA_DBG_WATCH_MODE WatchMode[],
					      void *WatchAddress[],
					      HSAuint64 WatchMask[],
					      HsaEvent *WatchEvent[])
{
	HSAKMT_STATUS result;
	uint32_t gpu_id;

	/* determine the size of the watch mask and event buffers
	 * the value is NULL if and only if no vector data should be attached
	 */
	uint32_t watch_mask_items = WatchMask[0] > 0 ? NumWatchPoints:1;
	uint32_t watch_event_items = WatchEvent != NULL ? NumWatchPoints:0;

	struct kfd_ioctl_dbg_address_watch_args *args;
	HSAuint32		 i = 0;

	CHECK_KFD_OPEN();

	result = validate_nodeid(NodeId, &gpu_id);
	if (result != HSAKMT_STATUS_SUCCESS)
		return result;

	if (NumWatchPoints > MAX_ALLOWED_NUM_POINTS)
		return HSAKMT_STATUS_INVALID_PARAMETER;

	/* Size and structure of the ioctl buffer is dynamic in this case
	 * Here we calculate the buff size.
	 */
	uint32_t buff_size = sizeof(NumWatchPoints) +
		(sizeof(WatchMode[0]) + sizeof(WatchAddress[0])) *
			NumWatchPoints +
		watch_mask_items * sizeof(HSAuint64) +
		watch_event_items * sizeof(HsaEvent *) + sizeof(*args);

	args = (struct kfd_ioctl_dbg_address_watch_args *) malloc(buff_size);
	if (!args)
		return HSAKMT_STATUS_ERROR;

	memset(args, 0, buff_size);

	args->gpu_id = gpu_id;
	args->buf_size_in_bytes = buff_size;


	/* increment pointer to the start of the non fixed part */
	unsigned char *run_ptr = (unsigned char *)args + sizeof(*args);

	/* save variable content pointer for kfd */
	args->content_ptr = (uint64_t)run_ptr;
	/* insert items, and increment pointer accordingly */

	*((HSAuint32 *)run_ptr) = NumWatchPoints;
	run_ptr += sizeof(NumWatchPoints);

	for (i = 0; i < NumWatchPoints; i++) {
		*((HSA_DBG_WATCH_MODE *)run_ptr) = WatchMode[i];
		run_ptr += sizeof(WatchMode[i]);
	}

	for (i = 0; i < NumWatchPoints; i++) {
		*((void **)run_ptr) = WatchAddress[i];
		run_ptr += sizeof(WatchAddress[i]);
	}

	for (i = 0; i < watch_mask_items; i++) {
		*((HSAuint64 *)run_ptr) = WatchMask[i];
		run_ptr += sizeof(WatchMask[i]);
	}

	for (i = 0; i < watch_event_items; i++)	{
		*((HsaEvent **)run_ptr) = WatchEvent[i];
		run_ptr += sizeof(WatchEvent[i]);
	}

	/* send to kernel */
	long err = kmtIoctl(kfd_fd, AMDKFD_IOC_DBG_ADDRESS_WATCH, args);

	free(args);

	if (err)
		return HSAKMT_STATUS_ERROR;
	return HSAKMT_STATUS_SUCCESS;
}

int debug_get_reg_status(uint32_t node_id, bool *is_debugged)
{
	*is_debugged = NULL;
	if (!is_device_debugged)
		return -1;

	*is_debugged = is_device_debugged[node_id];
	return 0;
}

static HSAKMT_STATUS debug_trap(HSAuint32 NodeId,
				HSAuint32 op,
				HSAuint32 data1,
				HSAuint32 data2,
				HSAuint32 data3,
				HSAuint32 pid,
				HSAuint64 pointer
				)
{
	uint32_t gpu_id;
	HSAKMT_STATUS result;
	HsaNodeProperties NodeProperties = {0};
	struct kfd_ioctl_dbg_trap_args args = {0};

	CHECK_KFD_OPEN();

	if (op == KFD_IOC_DBG_TRAP_NODE_SUSPEND ||
			op == KFD_IOC_DBG_TRAP_NODE_RESUME) {
		if  (NodeId != INVALID_NODEID)
			return HSAKMT_STATUS_INVALID_HANDLE;

		// gpu_id is ignored for suspend/resume queues.
		gpu_id = INVALID_NODEID;
	} else {
		if (validate_nodeid(NodeId, &gpu_id) != HSAKMT_STATUS_SUCCESS)
			return HSAKMT_STATUS_INVALID_HANDLE;

		result = hsaKmtGetNodeProperties(NodeId, &NodeProperties);

		if (result != HSAKMT_STATUS_SUCCESS)
			return result;

		if (!NodeProperties.Capability.ui32.DebugTrapSupported)
			return HSAKMT_STATUS_NOT_SUPPORTED;
	}

	if (pid == INVALID_PID) {
		pid = (HSAuint32) getpid();
	}

	memset(&args, 0x00, sizeof(args));
	args.gpu_id = gpu_id;
	args.op = op;
	args.data1 = data1;
	args.data2 = data2;
	args.data3 = data3;
	args.pid = pid;
	args.ptr = pointer;

	long err = kmtIoctl(kfd_fd, AMDKFD_IOC_DBG_TRAP, &args);

	if (err == 0)
		result = HSAKMT_STATUS_SUCCESS;
	else
		result = HSAKMT_STATUS_ERROR;

	return result;
}

HSAKMT_STATUS HSAKMTAPI hsaKmtEnableDebugTrap(HSAuint32   NodeId,
					      HSA_QUEUEID QueueId)
{
	if (QueueId != INVALID_QUEUEID)
		return HSAKMT_STATUS_NOT_SUPPORTED;

	return debug_trap(NodeId,
				KFD_IOC_DBG_TRAP_ENABLE,
				1,
				QueueId,
				0,
				INVALID_PID,
				0);
}

HSAKMT_STATUS HSAKMTAPI hsaKmtDisableDebugTrap(HSAuint32 NodeId)
{
	return  debug_trap(NodeId,
			KFD_IOC_DBG_TRAP_ENABLE,
			0,
			0,
			0,
			INVALID_PID,
			0);
}

HSAKMT_STATUS HSAKMTAPI hsaKmtSetDebugTrapData2(HSAuint32 NodeId,
					       HSAuint32 TrapData0,
					       HSAuint32 TrapData1)
{
	return debug_trap(NodeId,
				KFD_IOC_DBG_TRAP_SET_TRAP_DATA,
				TrapData0,
				TrapData1,
				0,
				INVALID_PID,
				0);
}

HSAKMT_STATUS HSAKMTAPI hsaKmtSetWaveLaunchTrapOverride(
					HSAuint32 NodeId,
					HSA_DBG_TRAP_OVERRIDE TrapOverride,
					HSA_DBG_TRAP_MASK     TrapMask)
{
	if (TrapOverride >= HSA_DBG_TRAP_OVERRIDE_NUM)
		return HSAKMT_STATUS_INVALID_PARAMETER;

	return debug_trap(NodeId,
				KFD_IOC_DBG_TRAP_SET_WAVE_LAUNCH_OVERRIDE,
				TrapOverride,
				TrapMask,
				0,
				INVALID_PID,
				0);
}

HSAKMT_STATUS HSAKMTAPI hsaKmtSetWaveLaunchMode(
				HSAuint32 NodeId,
				HSA_DBG_WAVE_LAUNCH_MODE WaveLaunchMode)
{
	return debug_trap(NodeId,
				KFD_IOC_DBG_TRAP_SET_WAVE_LAUNCH_MODE,
				WaveLaunchMode,
				0,
				0,
				INVALID_PID,
				0);
}

/**
 *   Suspend the execution of a set of queues. A queue that is suspended
 *   allows the wave context save state to be inspected and modified. If a
 *   queue is already suspended it remains suspended. A suspended queue
 *   can be resumed by hsaKmtDbgQueueResume().
 *
 *   For each node that has a queue suspended, a sequentially consistent
 *   system scope release will be performed that synchronizes with a
 *   sequentially consistent system scope acquire performed by this
 *   call. This ensures any memory updates performed by the suspended
 *   queues are visible to the thread calling this operation.
 *
 *   Pid is the process that owns the queues that are to be supended or
 *   resumed. If the value is -1 then the Pid of the process calling
 *   hsaKmtQueueSuspend or hsaKmtQueueResume is used.
 *
 *   NumQueues is the number of queues that are being requested to
 *   suspend or resume.
 *
 *   Queues is a pointer to an array with NumQueues entries of
 *   HSA_QUEUEID. The queues in the list must be for queues the exist
 *   for Pid, and can be a mixture of queues for different nodes.
 *
 *   GracePeriod is the number of milliseconds  to wait after
 *   initialiating context save before forcing waves to context save. A
 *   value of 0 indicates no grace period. It is ignored by
 *   hsaKmtQueueResume.
 *
 *   Flags is a bit set of the values defined by HSA_DBG_NODE_CONTROL.
 *   Returns:
 *    - HSAKMT_STATUS_SUCCESS if successful.
 *    - HSAKMT_STATUS_INVALID_HANDLE if any QueueId is invalid for Pid.
 */

HSAKMT_STATUS
HSAKMTAPI
hsaKmtQueueSuspend(
		HSAuint32    Pid,         // IN
		HSAuint32    NumQueues,   // IN
		HSA_QUEUEID *Queues,      // IN
		HSAuint32    GracePeriod, // IN
		HSAuint32    Flags)       // IN
{
	HSAKMT_STATUS result;
	uint32_t *queue_ids_ptr;

	CHECK_KFD_OPEN();

	queue_ids_ptr = convert_queue_ids(NumQueues, Queues);
	if (!queue_ids_ptr)
		return HSAKMT_STATUS_NO_MEMORY;

	result = debug_trap(INVALID_NODEID,
			KFD_IOC_DBG_TRAP_NODE_SUSPEND,
			Flags,
			NumQueues,
			GracePeriod,
			Pid,
			(HSAuint64)queue_ids_ptr);

	free(queue_ids_ptr);
	return result;
}
/**
 *   Resume the execution of a set of queues. If a queue is not
 *   suspended by hsaKmtDbgQueueSuspend() then it remains executing. Any
 *   changes to the wave state data will be used when the waves are
 *   restored. Changes to the control stack data will have no effect.
 *
 *   For each node that has a queue resumed, a sequentially consistent
 *   system scope release will be performed that synchronizes with a
 *   sequentially consistent system scope acquire performed by all
 *   queues being resumed. This ensures any memory updates performed by
 *   the thread calling this operation are visible to the resumed
 *   queues.
 *
 *   For each node that has a queue resumed, the instruction cache will
 *   be invalidated. This ensures any instruction code updates performed
 *   by the thread calling this operation are visible to the resumed
 *   queues.
 *
 *   Pid is the process that owns the queues that are to be supended or
 *   resumed. If the value is -1 then the Pid of the process calling
 *   hsaKmtQueueSuspend or hsaKmtQueueResume is used.
 *
 *   NumQueues is the number of queues that are being requested to
 *   suspend or resume.
 *
 *   Queues is a pointer to an array with NumQueues entries of
 *   HSA_QUEUEID. The queues in the list must be for queues the exist
 *   for Pid, and can be a mixture of queues for different nodes.
 *
 *   Flags is a bit set of the values defined by HSA_DBG_NODE_CONTROL.
 *   Returns:
 *    - HSAKMT_STATUS_SUCCESS if successful
 *    - HSAKMT_STATUS_INVALID_HANDLE if any QueueId is invalid.
 */

HSAKMT_STATUS
HSAKMTAPI
hsaKmtQueueResume(
		HSAuint32    Pid,         // IN
		HSAuint32    NumQueues,   // IN
		HSA_QUEUEID *Queues,      // IN
		HSAuint32    Flags)       // IN
{
	HSAKMT_STATUS result;
	uint32_t *queue_ids_ptr;

	CHECK_KFD_OPEN();

	queue_ids_ptr = convert_queue_ids(NumQueues, Queues);
	if (!queue_ids_ptr)
		return HSAKMT_STATUS_NO_MEMORY;

	result = debug_trap(INVALID_NODEID,
			KFD_IOC_DBG_TRAP_NODE_RESUME,
			Flags,
			NumQueues,
			0,
			Pid,
			(HSAuint64)queue_ids_ptr);
	free(queue_ids_ptr);
	return result;
}
