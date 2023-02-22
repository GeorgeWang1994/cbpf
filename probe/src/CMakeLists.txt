include(libscap)
include(libsinsp)

include_directories(.)
include_directories("${LIBSINSP_INCLUDE_DIRS}")
include_directories("../cgo")

set(SOURCE_FILES
		cgo/cgo_func.cpp
		cgo/event.cpp)

add_library(event SHARED ${SOURCE_FILES})
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

target_link_libraries(event
		sinsp)
install(TARGETS event
		DESTINATION bin)