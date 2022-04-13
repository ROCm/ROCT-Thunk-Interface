/*
 * Copyright (C) 2016-2018 Advanced Micro Devices, Inc. All Rights Reserved.
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
#include "KFDDBGTest.hpp"
#include <sys/ptrace.h>
#include <poll.h>
#include "linux/kfd_ioctl.h"
#include "KFDQMTest.hpp"
#include "PM4Queue.hpp"
#include "PM4Packet.hpp"
#include "Dispatch.hpp"
#include <string>

static const char* jump_to_trap_gfx = \
"\
shader jump_to_trap\n\
wave_size(32) \n\
type(CS)\n\
/*copy the parameters from scalar registers to vector registers*/\n\
    s_trap 1\n\
    v_mov_b32 v0, s0\n\
    v_mov_b32 v1, s1\n\
    v_mov_b32 v2, s2\n\
    v_mov_b32 v3, s3\n\
    flat_load_dword v4, v[0:1] slc    /*load target iteration value*/\n\
    s_waitcnt vmcnt(0)&lgkmcnt(0)\n\
    v_mov_b32 v5, 0\n\
LOOP:\n\
    v_add_co_u32 v5, vcc, 1, v5\n\
    s_waitcnt vmcnt(0)&lgkmcnt(0)\n\
    /*compare the result value (v5) to iteration value (v4),*/\n\
    /*and jump if equal (i.e. if VCC is not zero after the comparison)*/\n\
    v_cmp_lt_u32 vcc, v5, v4\n\
    s_cbranch_vccnz LOOP\n\
    flat_store_dword v[2,3], v5\n\
    s_waitcnt vmcnt(0)&lgkmcnt(0)\n\
    s_endpgm\n\
    end\n\
";

static const char* trap_handler_gfx = \
"\
shader trap_handler\n\
wave_size(32) \n\
type(CS)\n\
CHECK_VMFAULT:\n\
    /*if trap jumped to by vmfault, restore skip m0 signalling*/\n\
    s_getreg_b32 ttmp14, hwreg(HW_REG_TRAPSTS)\n\
    s_and_b32 ttmp2, ttmp14, 0x800\n\
    s_cbranch_scc1 RESTORE_AND_EXIT\n\
GET_DOORBELL:\n\
    s_mov_b32 ttmp2, exec_lo\n\
    s_mov_b32 ttmp3, exec_hi\n\
    s_mov_b32 exec_lo, 0x80000000\n\
    s_sendmsg 10\n\
WAIT_SENDMSG:\n\
    /*wait until msb is cleared (i.e. doorbell fetched)*/\n\
    s_nop 7\n\
    s_bitcmp0_b32 exec_lo, 0x1F\n\
    s_cbranch_scc0 WAIT_SENDMSG\n\
SEND_INTERRUPT:\n\
    /* set context bit and doorbell and restore exec*/\n\
    s_mov_b32 exec_hi, ttmp3\n\
    s_and_b32 exec_lo, exec_lo, 0xfff\n\
    s_mov_b32 ttmp3, exec_lo\n\
    s_bitset1_b32 ttmp3, 23\n\
    s_mov_b32 exec_lo, ttmp2\n\
    s_mov_b32 ttmp2, m0\n\
    /* set m0, send interrupt and restore m0 and exit trap*/\n\
    s_mov_b32 m0, ttmp3\n\
    s_nop 0x0\n\
    s_sendmsg sendmsg(MSG_INTERRUPT)\n\
    s_mov_b32 m0, ttmp2\n\
RESTORE_AND_EXIT:\n\
    /* restore and increment program counter to skip shader trap jump*/\n\
    s_add_u32 ttmp0, ttmp0, 4\n\
    s_addc_u32 ttmp1, ttmp1, 0\n\
    s_and_b32 ttmp1, ttmp1, 0xffff\n\
    /* restore SQ_WAVE_IB_STS */\n\
    s_lshr_b32 ttmp2, ttmp11, (26 - 15)\n\
    s_and_b32 ttmp2, ttmp2, (0x8000 | 0x1F0000)\n\
    s_setreg_b32 hwreg(HW_REG_IB_STS), ttmp2\n\
    /* restore SQ_WAVE_STATUS */\n\
    s_and_b64 exec, exec, exec\n\
    s_and_b64 vcc, vcc, vcc\n\
    s_setreg_b32 hwreg(HW_REG_STATUS), ttmp12\n\
    s_rfe_b64 [ttmp0, ttmp1]\n\
    end\n\
";

void KFDDBGTest::SetUp() {
    ROUTINE_START

    KFDBaseComponentTest::SetUp();

    ROUTINE_END
}

void KFDDBGTest::TearDown() {
    ROUTINE_START

    /* Reset the user trap handler */
    hsaKmtSetTrapHandler(m_NodeInfo.HsaDefaultGPUNode(), 0, 0, 0, 0);

    KFDBaseComponentTest::TearDown();

    ROUTINE_END
}

/*
 * To test debug attaching to a spawned process (i.e. attach prior to the tracee
 * opening a KFD device), have the child request the parent to PTRACE attach and
 * wait for the parent to debug attach then allow the child to runtime enable.
 *
 * The following will be exercised:
 * - The KFD shall create a KFD process on behalf of the tracee during debug
 *   attach since the tracee has not opened a KFD device.
 * - Runtime enable on the tracee shall raise an event to the debugging parent
 *   and block until parent has signalled that it has recieved the runtime
 *   enable event.
 * - Tracee should follow a similar hand shake for runtime disable and debug
 *   detach should follow.
 *
 * */
TEST_F(KFDDBGTest, AttachToSpawnedProcess) {
    TEST_START(TESTPROFILE_RUNALL)
    if (m_FamilyId >= FAMILY_AI) {

        if (hsaKmtCheckRuntimeDebugSupport()) {
            LOG() << "Skip test as debug API not supported";
            goto exit;
        }

        pid_t childPid = fork();

        if (childPid == 0) { /* Debugged process */
            uint32_t rDebug;
            int r;

            /* Let parent become the debugger and wait for attach. */
            ptrace(PTRACE_TRACEME);
            raise(SIGSTOP);

            r = hsaKmtOpenKFD();

            if (r != HSAKMT_STATUS_SUCCESS) {
                WARN() << "KFD open failed in debugged process" << std::endl;
                exit(1);
            }

            LOG() << std::dec << "--- Debugged PID " << getpid() << " runtime enable" << std::endl;

            r = hsaKmtRuntimeEnable(&rDebug, true);

            if (r != HSAKMT_STATUS_SUCCESS) {
                WARN() << "Runtime enabled failed" << std::endl;
                exit(1);
            }

            LOG() << std::dec << "--- Debugged PID " << getpid() << " runtime disable and exit" << std::endl;

            hsaKmtRuntimeDisable();

            exit(0);
        } else {
            BaseDebug *debug = new BaseDebug();
            struct kfd_runtime_info r_info = {0};
            uint64_t runtimeMask = KFD_EC_MASK(EC_PROCESS_RUNTIME);
            int childStatus;

            waitpid(childPid, &childStatus, 0);
            while (!WIFSTOPPED(childStatus));

            /* Attach and let new debugged process continue with runtime enable */
            LOG() << std::dec << "Attaching to PID " << childPid  << std::endl;
            ASSERT_SUCCESS(debug->Attach(&r_info, sizeof(r_info), childPid, runtimeMask));
            ASSERT_EQ(r_info.runtime_state, DEBUG_RUNTIME_STATE_DISABLED);
            ASSERT_EQ(r_info.ttmp_setup, false);

            ptrace(PTRACE_CONT, childPid, NULL, NULL);

            /* Wait and unblock runtime enable */
            ASSERT_SUCCESS(debug->QueryDebugEvent(&runtimeMask, NULL, NULL, 5000));
            ASSERT_EQ(runtimeMask, KFD_EC_MASK(EC_PROCESS_RUNTIME));
            ASSERT_SUCCESS(debug->SendRuntimeEvent(runtimeMask, 0, 0));

            /* Wait and unblock runtime disable */
            ASSERT_SUCCESS(debug->QueryDebugEvent(&runtimeMask, NULL, NULL, 5000));
            ASSERT_EQ(runtimeMask, KFD_EC_MASK(EC_PROCESS_RUNTIME));
            ASSERT_SUCCESS(debug->SendRuntimeEvent(runtimeMask, 0, 0));

            LOG() << std::dec << "Detaching from PID " << childPid << std::endl;
            debug->Detach();

            ptrace(PTRACE_DETACH, childPid, NULL, NULL);

            LOG() << std::dec << "Waiting on PID " << childPid << " to exit" << std::endl;
            waitpid(childPid, &childStatus, 0);
            EXPECT_EQ(WIFEXITED(childStatus), true);
            EXPECT_EQ(WEXITSTATUS(childStatus), HSAKMT_STATUS_SUCCESS);
        }
    } else {
        LOG() << "Skipping test: Test not supported on family ID 0x"
              << m_FamilyId << "." << std::endl;
    }
exit:
    LOG() << std::endl;
    TEST_END
}

/*
 * Unlike AttachToSpawnedProcess, the debug parent will only attach after
 * a non-blocked runtime enable by the tracee.  The parent should expect
 * a status update that the tracee is runtime enabled on debug attach.
 * Cleanup with appropriate runtime disable and debug detach handshake.
 */
TEST_F(KFDDBGTest, AttachToRunningProcess) {
    TEST_START(TESTPROFILE_RUNALL)
    if (m_FamilyId >= FAMILY_AI) {

        if (hsaKmtCheckRuntimeDebugSupport()) {
            LOG() << "Skip test as debug API not supported";
            goto exit;
        }

    pid_t childPid = fork();

    if (childPid == 0) { /* Debugged process */
            uint32_t rDebug;
            int r;

            r = hsaKmtOpenKFD();

            if (r != HSAKMT_STATUS_SUCCESS) {
                WARN() << "KFD open failed in debugged process" << std::endl;
                exit(1);
             }

             LOG() << std::dec << "--- Debugged PID " << getpid() << " runtime enable" << std::endl;

             r = hsaKmtRuntimeEnable(&rDebug, true);
             if (r != HSAKMT_STATUS_SUCCESS) {
                 WARN() << "Runtime enabled failed" << std::endl;
                 exit(1);
             }

             /* Let parent become the debugger and wait for attach. */
             ptrace(PTRACE_TRACEME);
             raise(SIGSTOP);

             LOG() << std::dec << "--- Debugged PID " << getpid() << " runtime disable and exit" << std::endl;

             hsaKmtRuntimeDisable();

             exit(0);
        } else {
            BaseDebug *debug = new BaseDebug();
            struct kfd_runtime_info r_info = {0};
            uint64_t runtimeMask = KFD_EC_MASK(EC_PROCESS_RUNTIME);
            int childStatus;

            waitpid(childPid, &childStatus, 0);
            while (!WIFSTOPPED(childStatus));

            /* Attach to running process and let it continue */
            LOG() << std::dec << "Attaching to PID " << childPid  << std::endl;
            ASSERT_SUCCESS(debug->Attach(&r_info, sizeof(r_info), childPid, runtimeMask));
            ASSERT_EQ(r_info.runtime_state, DEBUG_RUNTIME_STATE_ENABLED);
            ASSERT_EQ(r_info.ttmp_setup, true);

            ptrace(PTRACE_CONT, childPid, NULL, NULL);

            /* Wait and unblock runtime disable */
            ASSERT_SUCCESS(debug->QueryDebugEvent(&runtimeMask, NULL, NULL, 5000));
            ASSERT_EQ(runtimeMask, KFD_EC_MASK(EC_PROCESS_RUNTIME));
            ASSERT_SUCCESS(debug->SendRuntimeEvent(runtimeMask, 0, 0));

            LOG() << std::dec << "Detaching from PID " << childPid << std::endl;
            debug->Detach();

            ptrace(PTRACE_DETACH, childPid, NULL, NULL);

            LOG() << std::dec << "Waiting on PID " << childPid << " to exit" << std::endl;
            waitpid(childPid, &childStatus, 0);
            EXPECT_EQ(WIFEXITED(childStatus), true);
            EXPECT_EQ(WEXITSTATUS(childStatus), HSAKMT_STATUS_SUCCESS);
        }
    } else {
        LOG() << "Skipping test: Test not supported on family ID 0x"
              << m_FamilyId << "." << std::endl;
    }
exit:
    LOG() << std::endl;
    TEST_END
}
