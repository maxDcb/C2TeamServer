## ssl certificat for https listener
if(WIN32)	
else()
	file(COPY ${CMAKE_SOURCE_DIR}/certs/sslBeaconHttps DESTINATION ${CMAKE_BINARY_DIR}/certs)

	execute_process(COMMAND bash -c "cd ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps && ./genSslCert.sh localhost")

	file(COPY ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps/localhost.key DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	#file(RENAME ${CMAKE_SOURCE_DIR}/Release/TeamServer/localhost.key ${CMAKE_SOURCE_DIR}/Release/TeamServer/localhost.key)

	file(COPY ${CMAKE_BINARY_DIR}/certs/sslBeaconHttps/localhost.crt DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	#file(RENAME ${CMAKE_SOURCE_DIR}/Release/TeamServer/localhost.crt ${CMAKE_SOURCE_DIR}/Release/TeamServer/localhost.crt)

endif()

## ssl certificat for TeamServer
if(WIN32)	
else()
	file(COPY ${CMAKE_SOURCE_DIR}/certs/sslTeamServ DESTINATION ${CMAKE_BINARY_DIR}/certs)

	execute_process(COMMAND bash -c "cd ${CMAKE_BINARY_DIR}/certs/sslTeamServ && ./genSslCert.sh")

	# server.key
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/server-key.pem DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	file(RENAME ${CMAKE_SOURCE_DIR}/Release/TeamServer/server-key.pem ${CMAKE_SOURCE_DIR}/Release/TeamServer/server.key)

	# server.crt
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/server.pem DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	file(RENAME ${CMAKE_SOURCE_DIR}/Release/TeamServer/server.pem ${CMAKE_SOURCE_DIR}/Release/TeamServer/server.crt)

	# rootCA.crt
	file(COPY ${CMAKE_BINARY_DIR}/certs/sslTeamServ/ca.pem DESTINATION ${CMAKE_SOURCE_DIR}/Release/TeamServer/)
	file(RENAME ${CMAKE_SOURCE_DIR}/Release/TeamServer/ca.pem ${CMAKE_SOURCE_DIR}/Release/TeamServer/rootCA.crt)
endif()