## ssl certificat for https listener
if(WIN32)	
else()
	file(COPY ${CMAKE_SOURCE_DIR}/certs/sslBeaconHttps DESTINATION ${CMAKE_BINARY_DIR}/certs)

	execute_process(COMMAND bash -c "cd ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps && ./genSslCert.sh localhost")

	file(COPY ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps/localhost.key DESTINATION ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/)

	file(COPY ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps/localhost.crt DESTINATION ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/)

endif()

## ssl certificat for TeamServer
if(WIN32)	
else()
	file(COPY ${CMAKE_SOURCE_DIR}/certs/sslTeamServ DESTINATION ${CMAKE_BINARY_DIR}/certs)

	execute_process(COMMAND bash -c "cd ${CMAKE_BINARY_DIR}/certs/sslTeamServ && ./genSslCert.sh")

	# server.key
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/server-key.pem DESTINATION ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/)
	file(RENAME ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/server-key.pem ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/server.key)

	# server.crt
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/server.pem DESTINATION ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/)
	file(RENAME ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/server.pem ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/server.crt)

	# rootCA.crt
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/ca.pem DESTINATION ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/)
	file(RENAME ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/ca.pem ${C2_TEAMSERVER_RUNTIME_OUTPUT_DIR}/rootCA.crt)
endif()
