#include <cstdio>
#include <iostream>
#include <cstdlib>
#include "sinsp.h"
#include "src/probe/utils/termination_handler.h"
#include <unistd.h>
#include <sys/un.h>
#include "src/probe/converter/sysdig_converter.h"
#include "src/probe/publisher/publisher.h"
#include "src/probe/converter/kindling_event.pb.h"
#include "driver/driver_config.h"
#include "src/common/base/base.h"

DEFINE_int32(sysdig_snaplen, 80, "The len of one sysdig event");
DEFINE_int32(list_batch_size, 100, "The batch size of convert/send list");
DEFINE_int32(list_max_size, INT_MAX, "The max size of convert/send list");
DEFINE_bool(sysdig_output, false, "If true, sysdig will print events log");
DEFINE_int32(sysdig_filter_out_pid_event, -1, "When sysdig_output is true, sysdig will print the exact process's events");
DEFINE_bool(sysdig_bpf, true, "If true, sysdig will use eBPF mode");


#define PROBE_VERSION "v0.1"

void do_inspect(sinsp *inspector, sinsp_evt_formatter *formatter, int pid, publisher* pub) {
    int32_t res;
    sinsp_evt *ev;
    string line;
    converter *sysdigConverter = new sysdig_converter(inspector, FLAGS_list_batch_size, FLAGS_list_max_size);
    while (true) {
        res = inspector->next(&ev);
        if (res == SCAP_TIMEOUT) {
            continue;
        } else if (res != SCAP_SUCCESS) {
            cerr << "res = " << res << endl;
            break;
        }
        if (!inspector->is_debug_enabled() &&
            ev->get_category() & EC_INTERNAL) {
            continue;
        }
        auto threadInfo = ev->get_thread_info();
        if (threadInfo == nullptr) {
            continue;
        }
        // filter out kindling-probe itself and 0
        if (threadInfo->m_ptid == (__int64_t) pid || threadInfo->m_pid == (__int64_t) pid || threadInfo->m_pid == 0) {
            continue;
        }

        // filter out io-related events that do not contain message
        auto category = ev->get_category();
        if (category & EC_IO_BASE) {
            auto pres = ev->get_param_value_raw("res");
            if (pres && *(int64_t *) pres->m_val <= 0) {
                continue;
            }
        }

        pub->consume_sysdig_event(ev, threadInfo->m_pid, sysdigConverter);
        if (FLAGS_sysdig_output && (FLAGS_sysdig_filter_out_pid_event == -1 || FLAGS_sysdig_filter_out_pid_event == threadInfo->m_pid)) {
            if (formatter->tostring(ev, &line)) {
                cout<< line << endl;
            }
        }
    }
}


