add_executable(testClient "testClient.cpp" )
if(WIN32)
	target_link_libraries(testClient SocketHandler boost::boost spdlog::spdlog )
else()
	target_link_libraries(testClient SocketHandler boost::boost pthread spdlog::spdlog )
endif()


add_executable(testServer "testServer.cpp" )
if(WIN32)
	target_link_libraries(testServer SocketHandler boost::boost spdlog::spdlog )
else()
	target_link_libraries(testServer SocketHandler boost::boost pthread spdlog::spdlog )
endif()
