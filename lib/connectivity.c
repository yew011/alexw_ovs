/*
 * Copyright (c) 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "backtrace.h"
#include "connectivity.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "seq.h"
#include "unixctl.h"

/* Provides a global seq for connectivity changes.
 *
 * Connectivity monitoring modules should use the public functions in this
 * module to report, check or wait on link/port status change.
 * */
static struct seq *connectivity_seq;
static atomic_bool log_source = ATOMIC_VAR_INIT(false);

static void
connectivity_unixctl_enable_log_source(struct unixctl_conn *conn,
                                       int argc OVS_UNUSED,
                                       const char *argv[] OVS_UNUSED,
                                       void *aux OVS_UNUSED)
{
    atomic_store(&log_source, true);
    unixctl_command_reply(conn, "log source enabled");
}

static void
connectivity_unixctl_disable_log_source(struct unixctl_conn *conn,
                                        int argc OVS_UNUSED,
                                        const char *argv[] OVS_UNUSED,
                                        void *aux OVS_UNUSED)
{
    atomic_store(&log_source, false);
    unixctl_command_reply(conn, "log source disabled");
}

/* Runs only once to initialize 'connectivity_seq'. */
static void
connectivity_seq_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        connectivity_seq = seq_create();

        unixctl_command_register("connectivity/enable-log-source", "", 0, 0,
                                 connectivity_unixctl_enable_log_source, NULL);
        unixctl_command_register("connectivity/disable-log-source", "", 0, 0,
                                 connectivity_unixctl_disable_log_source, NULL);
        ovsthread_once_done(&once);
    }
}

/* Logs the calling stack. */
static void
log_call_stack(void)
{
    log_backtrace_msg("connectivity_seq");
}

/* Reads and returns the current 'connectivity_seq' value. */
uint64_t
connectivity_seq_read(void)
{
    connectivity_seq_init();

    return seq_read(connectivity_seq);
}

/* Changes the 'connectivity_seq'. */
void
connectivity_seq_change(void)
{
    bool log_enabled;

    connectivity_seq_init();

    atomic_read(&log_source, &log_enabled);
    if (log_enabled) {
        log_call_stack();
    }
    seq_change(connectivity_seq);
}

/* Wakes the caller up when 'connectivity_seq''s sequence number
 * changes from 'value'.  */
void
connectivity_seq_wait(uint64_t value)
{
    connectivity_seq_init();
    seq_wait(connectivity_seq, value);
}
