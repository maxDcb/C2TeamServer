## ssl certificat for https listener
if(WIN32)	
else()
	file(COPY ${CMAKE_SOURCE_DIR}/certs/sslBeaconHttps DESTINATION ${CMAKE_BINARY_DIR}/certs)

	execute_process(COMMAND bash -c "cd ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps && ./genSslCert.sh demo.c2.com")
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps/demo.c2.com.key DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	file(RENAME ${CMAKE_SOURCE_DIR}/Release/TeamServer/demo.c2.com.key ${CMAKE_SOURCE_DIR}/Release/TeamServer/key.pem)
	file(REMOVE ${CMAKE_SOURCE_DIR}/Release/TeamServer/demo.c2.com.key)
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps/demo.c2.com.crt DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	file(RENAME ${CMAKE_SOURCE_DIR}/Release/TeamServer/demo.c2.com.crt ${CMAKE_SOURCE_DIR}/Release/TeamServer/cert.pem)
	file(REMOVE ${CMAKE_SOURCE_DIR}/Release/TeamServer/demo.c2.com.crt)
endif()

## ssl certificat for TeamServer
if(WIN32)	
else()
	file(COPY ${CMAKE_SOURCE_DIR}/certs/sslTeamServ DESTINATION ${CMAKE_BINARY_DIR}/certs)

	execute_process(COMMAND bash -c "cd ${CMAKE_BINARY_DIR}/certs/sslTeamServ && ./genSslCert.sh")

	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/server-key.pem DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/server.pem DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/ca.pem DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/ca.pem DESTINATION ${CMAKE_SOURCE_DIR}/Release/Client/)
endif()