import sys
import os


def OnListenerStart(hash):
	print("OnListenerStart", hash)


def OnListenerStop(hash):
	print("OnListenerStop", hash)


def OnSessionStart(hash):
	print("OnSessionStart", hash)


def OnSessionStop(hash):
	print("OnSessionStop", hash)	


def OnConsoleSend(hash):
	print("OnConsoleSend", hash)	


def OnConsoleReceive(hash):
	print("OnConsoleReceive", hash)	