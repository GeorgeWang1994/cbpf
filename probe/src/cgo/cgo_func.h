#ifndef SYSDIG_CGO_FUNC_H
#define SYSDIG_CGO_FUNC_H

#ifdef __cplusplus
extern "C" {
#endif
void runForGo();
int getKindlingEvent(void **kindlingEvent);
void subEventForGo(char* eventName, char* category);
#ifdef __cplusplus
}
#endif

#endif //SYSDIG_CGO_FUNC_H
