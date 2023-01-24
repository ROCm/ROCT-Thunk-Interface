/*
 * Copyright (C) 2021 Advanced Micro Devices, Inc. All Rights Reserved.
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

#ifndef __KFD_BASE_DEBUG__H__
#define __KFD_BASE_DEBUG__H__

#include "hsakmt.h"
#include <poll.h>
#include <stdlib.h>

// @class BaseDebug
class BaseDebug {
 public:
    BaseDebug(void);
    virtual ~BaseDebug(void);

    bool IsVersionSupported(void);

    HSAKMT_STATUS Attach(struct kfd_runtime_info *rInfo,
                         int rInfoSize,
                         unsigned int pid,
                         uint64_t exceptionEnable);

    void Detach(void);
    HSAKMT_STATUS SendRuntimeEvent(uint64_t exceptions, int gpuId, int queueId);
    void SetExceptionsEnabled(uint64_t exceptions);
    HSAKMT_STATUS SuspendQueues(unsigned int *NumQueues, HSA_QUEUEID *Queues, uint32_t *QueueIds,
                                uint64_t ExceptionsToClear);
    HSAKMT_STATUS ResumeQueues(unsigned int *NumQueues, HSA_QUEUEID *Queues, uint32_t *QueueIds);
    HSAKMT_STATUS QueryDebugEvent(uint64_t *Exceptions,
                                  uint32_t *GpuId, uint32_t *QueueId,
                                  int TimeoutMsec);
    HSAKMT_STATUS QueueSnapshot(uint64_t ExceptionsToClear, uint64_t SnapshotBufAddr,
                                uint32_t *SnapshotSize);
    HSAKMT_STATUS DeviceSnapshot(uint64_t ExceptionsToClear, uint64_t SnapshotBuffAddr,
                                 uint32_t *SnapshotSize);
    HSAKMT_STATUS SetWaveLaunchOverride(int mode, uint32_t *enable_mask, uint32_t *support_mask);

 private:
    unsigned int m_Pid;
    struct pollfd m_Fd;
    const char *m_Fd_Name = "/tmp/dbg_fifo";
};

#endif  // __KFD_BASE_DEBUG__H__
