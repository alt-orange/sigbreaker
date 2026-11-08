"""Load a test DLL in a fresh process and invoke its exported test entry."""
import ctypes
import sys

ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
dll = ctypes.CDLL(sys.argv[1])
dll.run_case.argtypes = [ctypes.c_char_p]
dll.run_case.restype = ctypes.c_int
raise SystemExit(dll.run_case(sys.argv[2].encode('ascii')))
