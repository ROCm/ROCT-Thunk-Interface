/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "BaseDebug.hpp"
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/kfd_ioctl.h>
#include <fcntl.h>
#include "unistd.h"

BaseDebug::BaseDebug(void) {
}

BaseDebug::~BaseDebug(void) {
    /*
     * If the process is still attached, close and destroy the polling file
     * descriptor.  Note that on process termination, the KFD automatically
     * disables processes that are still runtime enabled and debug enabled
     * so we don't do it here.
     */
    if (m_Pid) {
        close(m_Fd.fd);
        unlink(m_Fd_Name);
    }
}

// Creates temp file descriptor and debug attaches.
HSAKMT_STATUS BaseDebug::Attach(struct kfd_runtime_info *rInfo,
                                int rInfoSize,
                                unsigned int pid,
                                uint64_t exceptionEnable) {
    struct kfd_ioctl_dbg_trap_args args = {0};
    char fd_name[32];

    memset(&args, 0x00, sizeof(args));

    mkfifo(m_Fd_Name, 0666);
    m_Fd.fd = open(m_Fd_Name, O_CLOEXEC | O_NONBLOCK | O_RDWR);
    m_Fd.events = POLLIN | POLLRDNORM;

    args.pid = pid;
    args.op = KFD_IOC_DBG_TRAP_ENABLE;
    args.enable.rinfo_ptr = (uint64_t)rInfo;
    args.enable.rinfo_size = rInfoSize;
    args.enable.dbg_fd = m_Fd.fd;
    args.enable.exception_mask = exceptionEnable;

    if (hsaKmtDebugTrapIoctl(&args, NULL, NULL)) {
        close(m_Fd.fd);
	unlink(m_Fd_Name);
        return HSAKMT_STATUS_ERROR;
    }

    m_Pid = pid;

    return HSAKMT_STATUS_SUCCESS;
}


void BaseDebug::Detach(void) {
    struct kfd_ioctl_dbg_trap_args args = {0};

    memset(&args, 0x00, sizeof(args));
    
    args.pid = m_Pid;
    args.op = KFD_IOC_DBG_TRAP_DISABLE;

    hsaKmtDebugTrapIoctl(&args, NULL, NULL);

    close(m_Fd.fd);
    unlink(m_Fd_Name);

    m_Pid = 0;
    m_Fd.fd = 0;
    m_Fd.events = 0;
}

HSAKMT_STATUS BaseDebug::SendRuntimeEvent(uint64_t exceptions, int gpuId, int queueId)
{
    struct kfd_ioctl_dbg_trap_args args = {0};

    memset(&args, 0x00, sizeof(args));

    args.pid = m_Pid;
    args.op = KFD_IOC_DBG_TRAP_SEND_RUNTIME_EVENT;
    args.send_runtime_event.exception_mask = exceptions;
    args.send_runtime_event.gpu_id;
    args.send_runtime_event.queue_id;

    return hsaKmtDebugTrapIoctl(&args, NULL, NULL);
}

void BaseDebug::SetExceptionsEnabled(uint64_t exceptions)
{
    struct kfd_ioctl_dbg_trap_args args = {0};

    memset(&args, 0x00, sizeof(args));

    args.pid = m_Pid;
    args.op = KFD_IOC_DBG_TRAP_SET_EXCEPTIONS_ENABLED;     
    args.set_exceptions_enabled.exception_mask = exceptions;

    hsaKmtDebugTrapIoctl(&args, NULL, NULL);
}

HSAKMT_STATUS BaseDebug::SuspendQueues(unsigned int *NumQueues,
                                       HSA_QUEUEID *Queues,
                                       uint32_t *QueueIds,
                                       uint64_t ExceptionsToClear)
{
    struct kfd_ioctl_dbg_trap_args args = {0};

    memset(&args, 0x00, sizeof(args));

    args.pid = m_Pid;
    args.op = KFD_IOC_DBG_TRAP_SUSPEND_QUEUES;
    args.suspend_queues.num_queues = *NumQueues;
    args.suspend_queues.queue_array_ptr = (uint64_t)QueueIds;
    args.suspend_queues.exception_mask = ExceptionsToClear;

    return hsaKmtDebugTrapIoctl(&args, Queues, (HSAuint64 *)NumQueues);
}

HSAKMT_STATUS BaseDebug::ResumeQueues(unsigned int *NumQueues,
                                       HSA_QUEUEID *Queues,
                                       uint32_t *QueueIds)
{
    struct kfd_ioctl_dbg_trap_args args = {0};

    memset(&args, 0x00, sizeof(args));

    args.pid = m_Pid;
    args.op = KFD_IOC_DBG_TRAP_RESUME_QUEUES;
    args.resume_queues.num_queues = *NumQueues;
    args.resume_queues.queue_array_ptr = (uint64_t)QueueIds;

    return hsaKmtDebugTrapIoctl(&args, Queues, (HSAuint64 *)NumQueues);
}

HSAKMT_STATUS BaseDebug::QueryDebugEvent(uint64_t *Exceptions,
                                         uint32_t *GpuId, uint32_t *QueueId,
                                         int TimeoutMsec)
{
    struct kfd_ioctl_dbg_trap_args args = {0};
    HSAKMT_STATUS result;
    int r = poll(&m_Fd, 1, TimeoutMsec);

    if (r > 0) {
        char tmp[r];

        read(m_Fd.fd, tmp, sizeof(tmp));
    } else {
        return HSAKMT_STATUS_ERROR;
    }

    memset(&args, 0x00, sizeof(args));

    args.pid = m_Pid;
    args.op = KFD_IOC_DBG_TRAP_QUERY_DEBUG_EVENT;
    args.query_debug_event.exception_mask = *Exceptions;

    result = hsaKmtDebugTrapIoctl(&args, NULL, NULL);

    *Exceptions = args.query_debug_event.exception_mask;

    if (GpuId)
        *GpuId = args.query_debug_event.gpu_id;

    if (QueueId)
        *QueueId = args.query_debug_event.queue_id;

    return result;
}

HSAKMT_STATUS BaseDebug::QueueSnapshot(uint64_t ExceptionsToClear,
                                  uint64_t SnapshotBufAddr,
                                  uint32_t *SnapshotSize)
{
    struct kfd_ioctl_dbg_trap_args args = {0};
    HSAKMT_STATUS result;

    memset(&args, 0x00, sizeof(args));

    args.pid = m_Pid;
    args.op = KFD_IOC_DBG_TRAP_GET_QUEUE_SNAPSHOT;
    args.queue_snapshot.exception_mask = ExceptionsToClear;
    args.queue_snapshot.snapshot_buf_ptr = SnapshotBufAddr;
    args.queue_snapshot.buf_size = *SnapshotSize;

    result = hsaKmtDebugTrapIoctl(&args, NULL, NULL);

    *SnapshotSize = args.queue_snapshot.buf_size;

    return result;
}

HSAKMT_STATUS BaseDebug::DeviceSnapshot(uint64_t ExceptionsToClear,
                                  uint64_t SnapshotBufAddr,
                                  uint32_t *SnapshotSize)
{
    struct kfd_ioctl_dbg_trap_args args = {0};
    HSAKMT_STATUS result;

    memset(&args, 0x00, sizeof(args));

    args.pid = m_Pid;
    args.op = KFD_IOC_DBG_TRAP_GET_DEVICE_SNAPSHOT;
    args.device_snapshot.exception_mask = ExceptionsToClear;
    args.device_snapshot.snapshot_buf_ptr = SnapshotBufAddr;
    args.device_snapshot.buf_size = *SnapshotSize;

    result = hsaKmtDebugTrapIoctl(&args, NULL, NULL);

    *SnapshotSize = args.device_snapshot.buf_size;

    return result;
}
