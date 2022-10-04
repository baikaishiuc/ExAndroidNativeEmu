import logging
import posixpath
import sys
import os

from unicorn import *
from unicorn.arm_const import *
from androidemu import emulator

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
import androidemu.utils.debug_utils
from androidemu.utils.chain_log import ChainLogger

import capstone
import traceback

g_cfd = ChainLogger(sys.stdout, "./eg-nmusic-jni2.txt")
logger = logging.getLogger(__name__)
g_open_trace = 0

def hook_code(uc, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08x out of range" % (address))
            sys.exit(-1)

        '''
        if (address == 0xCBC3673A):
            r6 = emu.mu.reg_read(UC_ARM_REG_R6)
            androidemu.utils.debug_utils.dump_memory(emu, sys.stdout, r6, r6+15)
            sys.exit(-1)
        '''
        #
        #androidemu.utils.debug_utils.dump_registers(uc, sys.stdout)
        if g_open_trace == 1:
            androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd, androidemu.utils.debug_utils.DUMP_REG_WRITE)
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)
    #
#


def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
#


def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
#


class MainActivity(metaclass=JavaClassDef, jvm_name="local/myapp/testnativeapp/MainActivity"):

    def __init__(self):
        pass

    @java_method_def(name='stringFromJNI', signature='()Ljava/lang/String;', native=True)
    def string_from_jni(self,uc):
        pass

    def test(self):
        pass
    #
#

class NeteaseMusicUtils(metaclass=JavaClassDef, jvm_name="com/netease/cloudmusic/utils/NeteaseMusicUtils"):

    def __init__(self):
        pass

    @java_method_def(name='serialdata', signature='ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=True)
    def serialdata(self, uc):
        pass

    #
#

emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java Class.
emulator.java_classloader.add_class(NeteaseMusicUtils)

emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

logging.basicConfig(level=logging.DEBUG, format='%(message)s')

lib_module = emulator.load_library("tests/bin/libpoison.so")

g_open_trace = 1

logger.info("Load Modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s " % (module.base, module.filename))

try:
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    url_path = '/api/ad/get'
    url_param='{"adextjson":"{\"terminal\":\"Pixel\",\"network\":1,\"op\":0,\"dev_type\":1,''\"resolution\":{\"width\":1080,\"height\":1794},\"adReqId\":\"135969040_1664792960619_9445\",\"imei\":\"352689081497921\",\"android_id\":\"MzUyNjg5MDgxNDk3OTIxCWFjOjM3OjQzOmExOmMwOmExCWQyMTdhYzIzYjM1ODcwMjkJNDljMzI5Y2ZlOWUzMjhjNw%3D%3D\",\"manufacturer\":\"google\",\"lbs\":\"{\\\"latitude\\\":\\\"4.9E-324\\\",\\\"longitude\\\":\\\"4.9E-324\\\"}\",\"newAgent\":\"Mozilla\\/5.0 (Linux; Android 8.1.0; Pixel Build\\/OPM4.171019.021.D1; wv) AppleWebKit\\/537.36 (KHTML, like Gecko) Version\\/4.0 Chrome\\/105.0.5195.136 Mobile Safari\\/537.36 NeteaseMusic\\/7.1.51.1589354697\"}","type_ids":"[\"190001_0\"]","header":"{}","e_r":"true"}'

    x = NeteaseMusicUtils()
    ret = x.serialdata(emulator, x, url_path, url_param)

    logger.info("Response from serialdata call: %s " % ret)

    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity.")

except UcError as e:
    print("Exit at %x " % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise