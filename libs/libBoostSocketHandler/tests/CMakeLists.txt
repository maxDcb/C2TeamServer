add_executable(testClient "testClient.cpp" )
if(WIN32)
	target_link_libraries(testClient SocketHandler ${Boost_LIBRARIES})
else()
	target_link_libraries(testClient SocketHandler ${Boost_LIBRARIES} pthread)
endif()


add_executable(testServer "testServer.cpp" )
if(WIN32)
	target_link_libraries(testServer SocketHandler ${Boost_LIBRARIES})
else()
	target_link_libraries(testServer SocketHandler ${Boost_LIBRARIES} pthread)
endif()
