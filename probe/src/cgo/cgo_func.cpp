#include "cgo_func.h"
#include "event.h"


void runForGo(){
	init_probe();
}

int getKindlingEvent(void **kindlingEvent){
	return getEvent(kindlingEvent);
}

void subEventForGo(char* eventName, char* category){
	sub_event(eventName, category);
}
