#include "src/probe/cgo/publisher.h"
#include <unistd.h>
#include <sys/un.h>
#include <string>
#include <iostream>
#include <zmq.h>
#include <regex>
#include "tuples.h"
#include <dirent.h>
#include "src/probe/cgo/constant.h"

using namespace std;

publisher::publisher(sinsp *inspector) {
    m_socket = NULL;
    m_selector = new selector(inspector);
    m_inspector = inspector;
    m_bind_address = new shared_unordered_map<string, Socket>;
    m_client_event_map = new shared_unordered_map<void *, vector<KindlingEventList *>>;
}

publisher::~publisher() {
    delete m_selector;
    delete m_bind_address;
    delete m_client_event_map;
}

void publisher::consume_sysdig_event(sinsp_evt *evt, int pid, converter *sysdigConverter) {
    if (!m_socket) {
        return;
    }

    // filter out pid in filter_pid
    for (int i : filter_pid) {
        if (i == pid) {
            return;
        }
    }
    // convert sysdig event to kindling event
    if (m_selector->select(evt->get_type(), ((sysdig_converter *) sysdigConverter)->get_kindling_category(evt))) {
        auto it = m_kindlingEventLists.find(sysdigConverter);
        KindlingEventList* kindlingEventList;
        if (it == m_kindlingEventLists.end()) {
            kindlingEventList = new KindlingEventList();
            m_kindlingEventLists[sysdigConverter] = kindlingEventList;
            m_ready[kindlingEventList] = false;
        } else {
            kindlingEventList = it->second;
        }

        if (sysdigConverter->judge_max_size()) {
            // check if the send list has sent
            if (m_ready[kindlingEventList]) {
                // drop event
                return;
            }
            swap_list(sysdigConverter, kindlingEventList);
        }

        sysdigConverter->convert(evt);
        // if send list was sent
        if (sysdigConverter->judge_batch_size() && !m_ready[kindlingEventList]) {
            swap_list(sysdigConverter, kindlingEventList);
        }

        sysdigConverter->convert(evt);
        // if send list was sent
        if (sysdigConverter->judge_batch_size() && !m_ready[kindlingEventList]) {
            swap_list(sysdigConverter, kindlingEventList);
        }

        sysdigConverter->convert(evt);
            // if send list was sent
            if (sysdigConverter->judge_batch_size() && !m_ready[kindlingEventList]) {
                swap_list(sysdigConverter, kindlingEventList);
            }
    }
}

void publisher::send_server(publisher *mpublisher) {
    LOG(INFO) << "Thread sender start";
    uint64_t total= 0;
    uint64_t msg_total_size = 0;
    while (true) {
        usleep(100000);
        for (auto list : mpublisher->m_kindlingEventLists) {
            auto pKindlingEventList = list.second;
            // flag == false
            if (!mpublisher->m_ready[pKindlingEventList]) {
                continue;
            }
            if (pKindlingEventList->kindling_event_list_size() > 0) {
                string msg;
                pKindlingEventList->SerializeToString(&msg);
                int num = pKindlingEventList->kindling_event_list_size();
                total = total + num;
                LOG(INFO) << "Send " << num << " kindling events, sending size: " << setprecision(2) <<
                    msg.length() / 1024.0 <<" KB. Total count of kindling events: " << total;
//                cout << pKindlingEventList->Utf8DebugString();
                zmq_send(mpublisher->m_socket, msg.data(), msg.size(), ZMQ_DONTWAIT);
                pKindlingEventList->clear_kindling_event_list();
            }
            mpublisher->m_ready[pKindlingEventList] = false;
        }
    }
}

// 初始化
Socket publisher::init_zeromq_rep_server() {
    void *context = zmq_ctx_new();
    void *socket = zmq_socket(context, ZMQ_REP);
    zmq_bind(socket, "ipc:///home/kindling/0");
    return socket;
}

Socket publisher::init_zeromq_push_server() {
    void *context = zmq_ctx_new();
    void *socket = zmq_socket(context, ZMQ_PUSH);
    return socket;
}





