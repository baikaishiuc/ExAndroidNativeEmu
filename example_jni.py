import logging
import posixpath
import sys
import os
import time

from unicorn import *
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
import androidemu.utils.debug_utils
from androidemu.utils.chain_log import ChainLogger

import capstone
import traceback

def cur_ts():
    return round(time.time() * 1000)

g_cfd = ChainLogger(sys.stdout, "./ins-jni.txt")
g_inst_count=0
g_inst_start_ts = cur_ts()
# Add debugging.
def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08X out of range"%(address,))
            sys.exit(-1)
        #androidemu.utils.debug_utils.dump_registers(emu, sys.stdout)
        androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd, androidemu.utils.debug_utils.DUMP_REG_WRITE)
        global g_inst_count
        g_inst_count += 1
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)
    #
#

def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)

    if (address == 0xCBC80640):
        logger.debug("read mutex")
        data = uc.mem_read(address, size)
        v = int.from_bytes(data, byteorder='little', signed=False)
        logger.debug(">>> Memory READ at 0x%08X, data size = %u,  data value = 0x%08X, pc: 0x%08X," % (address, size, v, pc))
    #
#

def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if (address == 0xCBC80640):
        logger.debug("write mutex")
        logger.debug(">>> Memory WRITE at 0x%08X, data size = %u, data value = 0x%08X, pc: 0x%08X" % (address, size, value, pc))
    #
#

class MainActivity(metaclass=JavaClassDef, jvm_name='local/myapp/testnativeapp/MainActivity'):

    def __init__(self):
        pass

    @java_method_def(name='stringFromJNI', signature='()Ljava/lang/String;', native=True)
    def string_from_jni(self, mu):
        pass

    def test(self):
        pass


logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG, format='%(message)s')

# Initialize emulator
emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java class.
emulator.java_classloader.add_class(MainActivity)
emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)

emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

# Load all libraries.
lib_module = emulator.load_library("tests/bin/libnative-lib_jni.so")

#androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

#logger.setLevel(5)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    g_inst_start_ts = cur_ts()
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    spent_ts = cur_ts() - g_inst_start_ts
    print("***** %d instruction spent %fms, %d inst/s" % (g_inst_count, spent_ts, g_inst_count * 1000 / spent_ts))

    # Do native stuff.
    main_activity = MainActivity()
    logger.info("Response from JNI call: %s" % main_activity.string_from_jni(emulator))

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise

