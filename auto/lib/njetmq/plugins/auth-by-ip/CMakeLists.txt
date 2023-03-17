include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
			${STDBOOL_H_PATH} ${STDINT_H_PATH})

add_library(mosquitto_auth_by_ip SHARED mosquitto_auth_by_ip.c)
set_target_properties(mosquitto_auth_by_ip PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)
set_target_properties(mosquitto_auth_by_ip PROPERTIES PREFIX "")

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_auth_by_ip RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
