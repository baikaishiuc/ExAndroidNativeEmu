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

from androidemu.java.classes.string import String
from androidemu.java.classes.list import List
from androidemu.java.classes.array import Array
from androidemu.java.constant_values import *
from androidemu.utils.chain_log import ChainLogger

import capstone
import traceback

_MODE_DUMP=1
_MODE_DEBUG=2

#_mode=_MODE_DUMP
_run_mode=_MODE_DEBUG

outfile=""
g_open_trace = 0
if _run_mode == _MODE_DUMP:
    outfile="./eg-nmusic-jni-dump.txt"
    g_open_trace=1
else:
    outfile="./eg-nmusic-jni-debug.txt"
    g_open_trace=0

g_cfd = ChainLogger(sys.stdout, outfile)
logger = logging.getLogger(__name__)

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

    @java_method_def(name='serialdata', signature='(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', native=True)
    def serialdata(self, uc):
        pass

    @java_method_def(name='deserialdata', signature='([B)I', native=True)
    def deserialdata(self, uc):
        pass

    @java_method_def(name='deserialdata2', signature='([B)[B', native=True)
    def deserialdata2(self, uc):
        pass

    @java_method_def(name='nativeInit', signature='(Landroid/content/Context;)V', native=True)
    def nativeInit(self, uc):
        pass

    #
#

class aHgb9(metaclass=JavaClassDef, jvm_name="com/netease/cloudmusic/utils/musicfile/aHgb9"):

    def __init__(self):
        pass

emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java Class.
emulator.java_classloader.add_class(NeteaseMusicUtils)
emulator.java_classloader.add_class(aHgb9)

if _run_mode == _MODE_DUMP:
    emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
    emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logger.setLevel(logging.DEBUG)

lib_module = emulator.load_library("tests/bin/libpoison.so")

logger.info("Load Modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s " % (module.base, module.filename))

try:
    # libpoison.so在调用了.init_array以后，替换掉了默认的JNI_onLoad
    #emulator.call_addr(lib_module, 0x722DD, emulator.java_vm.address_ptr, 0x00)
    jni_load_base = lib_module.base + 0x722DC
    emulator.call_native(jni_load_base + 1, emulator.java_vm.address_ptr, 0x00)
    #emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    url_path = '/api/ad/get'
    url_param= r'{"adextjson":"{\"terminal\":\"Pixel\",\"network\":1,\"op\":0,\"dev_type\":1,\"resolution\":{\"width\":1080,\"height\":1794},\"adReqId\":\"135969040_1664792960619_9445\",\"imei\":\"352689081497921\",\"android_id\":\"MzUyNjg5MDgxNDk3OTIxCWFjOjM3OjQzOmExOmMwOmExCWQyMTdhYzIzYjM1ODcwMjkJNDljMzI5Y2ZlOWUzMjhjNw%3D%3D\",\"manufacturer\":\"google\",\"lbs\":\"{\\\"latitude\\\":\\\"4.9E-324\\\",\\\"longitude\\\":\\\"4.9E-324\\\"}\",\"newAgent\":\"Mozilla\\/5.0 (Linux; Android 8.1.0; Pixel Build\\/OPM4.171019.021.D1; wv) AppleWebKit\\/537.36 (KHTML, like Gecko) Version\\/4.0 Chrome\\/105.0.5195.136 Mobile Safari\\/537.36 NeteaseMusic\\/7.1.51.1589354697\"}","type_ids":"[\"190001_0\"]","header":"{}","e_r":"true"}'

    jstr = String(url_param)
    x = NeteaseMusicUtils()

    logger.debug(url_param)

    #native_init_addr=lib_module.base + 0x58004
    #emulator.mu.mem_write(native_init_addr, int(0).to_bytes(1, byteorder="little"))

    #addr1 = lib_module.base + 0x57c5c
    #emulator.mu.mem_write(addr1, int(0xBFD5DF70).to_bytes(4, byteorder="little"))
    #val = int.from_bytes(emulator.mu.mem_read(addr1, 4), byteorder="little")
    #sys.exit(-1)

    #aes_key_addr = lib_module.base + 0x581CC
    #val = int.from_bytes(emulator.mu.mem_read(aes_key_addr, 4), byteorder="little")

    #g_open_trace = 1
    #emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)

    ret = x.serialdata(emulator, String(url_path), String(url_param))

    logger.info("Response from serialdata call: %s " % ret)

    url = "/api/sp/flow/status/v2"
    data = r'{"deviceid":"MzUzNjI3MDc2NTI2MjQ2CTAwOmE3OjEwOjkzOjY0OjU3CThmOTcyMzdlMjIzYTQxMjkJOTllYTY0YTY5NGZjZjM4ZA%3D%3D_android","header":{"URS_APPID":"9A655D8373C42875421957AA8A68FF2587AD2149DBBCE40400A376B554866AA1888BBDD2609A548EFA6B1B3C7AFAE500","appver":"7.1.51","buildver":"1589354697","channel":"tencent","deviceId":"MzUzNjI3MDc2NTI2MjQ2CTAwOmE3OjEwOjkzOjY0OjU3CThmOTcyMzdlMjIzYTQxMjkJOTllYTY0YTY5NGZjZjM4ZA%3D%3D","mobilename":"Nexus5X","ntes_kaola_ad":"1","os":"android","osver":"6.0.1","requestId":"1590242909868_120","resolution":"1794x1080","versioncode":"7001051"},"e_r":"true"}'
    ret = x.serialdata(emulator, String(url), String(data))
    assert ret.get_py_string() == "7864E6961DEBE314D37A79DE0DA65E18A929A43CC884C3FC8BFA3F5C0E6703D77C37C5061AD3E154C759DCAAFB4BDBEBC88BE124ED0DB67F31920F99D352F41D831BCA63DCC73E3AB46C7D4F3A21DAE78E602E28C29A5A8ED8EAFB0B0F303877F860B29AA6FF837735FD450DF2B07B21F8D67C0FD4245F45FAE376D11BF7DE23662D42B4F667802BEA82FABCCB9BD8637D7032D919829DF7F9E6A968D5486EF9CB4E7E36F41AD20EF52E41A0C70100327A6A97869580893315E111C23EE9D36CF0078363C4A07C9D9EA08B3A3379AF726409EE641327D9878C1807BE3298EE92A9676593C5A12DB9F1C6FF63D58D0098F534447259BE79AE63D93F0D65CB310741CF35709CF7B03676846D0A0A3D06D04602CA7D838C15CF052A7172C44C58CBC1CA6E6FE86BD833C545694EC4999D298778A1F0631141112CA712C5CC87C7DEC7ECEA06FA359A45DBACAE2C3823130802E381E2F5808BA6F2119C6D53670489CE6963D87B677BC9B3ECE3C5FF1012ACA23960B24630FA5ECDC0D5169A18805AACDE525AA72E3FC71D179EE7C072ED1F7ED1900D86570C6D1E028AD4E92D0D358A747226136A7599673310A6D91FA60465EC82DC58B606C4EE098C63CBA210D3249AFFF23BBE51DF4FDE60D450F47F427020A703647F085134020D176CDD303D2B323085B0BF8F495B0C153431773FF7C89D8DD2D46E5E0BA1FBE8DF6E956BF5934E9146C02E6F39DBBA44ECE071D8B7F48433C67E6B0A88CB8D37D5C28CC11A4175E4C6949895F4D9FD68DCF580D75A1B63B85DC75574ED1D09C21C03081EDA0DF37F3AC8B2C96B65CEE3B9B0B2B62E107A5D0380A84C0BE4AA186760417DD4BCF431ADBBB5FA9337C2BB5A3DE4984DA381437E3DCD5084EEE1A4AA50013BDA10262FC208FC19E22C5BDF4543E724AD1375DE1F703FAA1BBBE6F38621B79080"

    url = '/api/comment/expression/list'
    data = '{"updateTime":"1664614080216","header":"{}","e_r":"true"}'
    ret = x.serialdata(emulator, String(url), String(data))
    assert ret.get_py_string() == 'FDC2E20A14820D14CC9CBA76BA7D59CD62CCF942BA072C40655698D7243B450C15820CF466927F790374B4C915A7E01B6A78A6E5B83FCC71F73A1B9DA1C255F52095D56568C05B85F56266C76796629A90422F94E9D167F6636761D72C00BD33667B503A32C6C2CF207B99D6B91F047B23AFE6244DF8EB29EFDB8C1DA80BAA2FEE49BCA41900013F1BBE9E6BAD544327'

    hexstr = '97AC17DCB2022CB205F7528F55CCFD1D7D4007A59C4550C35F3B16ACF919E92F2BD8D803B3738D5B76516AA19DF7276F42FFA3919DD4ADA500FE7E14A553C062E80A1257869071FA5E33963D04BE2A5A436E78FB5F41CEB4CA2E2B5EAFDCDB5E'
    data = Array(bytearray(bytes.fromhex(hexstr)))
    ret = x.deserialdata2(emulator, data)
    assert ret.get_py_items() == bytearray(b'{"status":{"status":0,"cellphone":null,"expireTime":0,"spType":-1,"packageName":""},"code":200}')

    logger.info("Exited EMU.")

except UcError as e:
    print("Exit at %x " % emulator.mu.reg_read(UC_ARM_REG_PC))
    androidemu.utils.debug_utils.dump_registers(emulator, sys.stdout)
    emulator.memory.dump_maps(sys.stdout)
    raise