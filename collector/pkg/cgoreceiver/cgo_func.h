#ifndef SYSDIG_CGO_FUNC_H
#define SYSDIG_CGO_FUNC_H

#ifdef __cplusplus
extern "C" {
#endif
void runForGo();
int getKindlingEvent(void **kindlingEvent);
int subEventForGo(char* eventName, char* category);
#ifdef __cplusplus
}
#endif
#endif //SYSDIG_CGO_FUNC_H

struct kindling_event_t_for_go{
	uint64_t timestamp;
	char *name;
	uint32_t category;
	uint16_t paramsNumber;
    struct KeyValue {
	char *key;
	char* value;
	uint32_t len;
	uint32_t valueType;
    }userAttributes[8];
    struct event_context {
        // 线程信息
        struct thread_info {
            uint32_t pid; // 进程id
            uint32_t tid; // 线程id
            uint32_t uid; // 用户id
            uint32_t gid; // 组id
            char *comm;
            char *containerId; // 容器id
        }tinfo;
        // fd信息
        struct fd_info {
            int32_t num;
            uint32_t fdType;
            char *filename;
            char *directory;
            uint32_t protocol;
            uint8_t role;
            uint32_t sip;
            uint32_t dip;
            uint32_t sport;
            uint32_t dport;
            uint64_t source;
            uint64_t destination;
        }fdInfo;
    }context;
};
