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
    logger.info("Response from serialdata call: %s " % ret)


    assert ret.get_py_string() == "7864E6961DEBE314D37A79DE0DA65E18A929A43CC884C3FC8BFA3F5C0E6703D77C37C5061AD3E154C759DCAAFB4BDBEBC88BE124ED0DB67F31920F99D352F41D831BCA63DCC73E3AB46C7D4F3A21DAE78E602E28C29A5A8ED8EAFB0B0F303877F860B29AA6FF837735FD450DF2B07B21F8D67C0FD4245F45FAE376D11BF7DE23662D42B4F667802BEA82FABCCB9BD8637D7032D919829DF7F9E6A968D5486EF9CB4E7E36F41AD20EF52E41A0C70100327A6A97869580893315E111C23EE9D36CF0078363C4A07C9D9EA08B3A3379AF726409EE641327D9878C1807BE3298EE92A9676593C5A12DB9F1C6FF63D58D0098F534447259BE79AE63D93F0D65CB310741CF35709CF7B03676846D0A0A3D06D04602CA7D838C15CF052A7172C44C58CBC1CA6E6FE86BD833C545694EC4999D298778A1F0631141112CA712C5CC87C7DEC7ECEA06FA359A45DBACAE2C3823130802E381E2F5808BA6F2119C6D53670489CE6963D87B677BC9B3ECE3C5FF1012ACA23960B24630FA5ECDC0D5169A18805AACDE525AA72E3FC71D179EE7C072ED1F7ED1900D86570C6D1E028AD4E92D0D358A747226136A7599673310A6D91FA60465EC82DC58B606C4EE098C63CBA210D3249AFFF23BBE51DF4FDE60D450F47F427020A703647F085134020D176CDD303D2B323085B0BF8F495B0C153431773FF7C89D8DD2D46E5E0BA1FBE8DF6E956BF5934E9146C02E6F39DBBA44ECE071D8B7F48433C67E6B0A88CB8D37D5C28CC11A4175E4C6949895F4D9FD68DCF580D75A1B63B85DC75574ED1D09C21C03081EDA0DF37F3AC8B2C96B65CEE3B9B0B2B62E107A5D0380A84C0BE4AA186760417DD4BCF431ADBBB5FA9337C2BB5A3DE4984DA381437E3DCD5084EEE1A4AA50013BDA10262FC208FC19E22C5BDF4543E724AD1375DE1F703FAA1BBBE6F38621B79080"


    url = '/api/comment/expression/list'
    data = '{"updateTime":"1664614080216","header":"{}","e_r":"true"}'
    ret = x.serialdata(emulator, String(url), String(data))

    assert ret.get_py_string() == 'FDC2E20A14820D14CC9CBA76BA7D59CD62CCF942BA072C40655698D7243B450C15820CF466927F790374B4C915A7E01B6A78A6E5B83FCC71F73A1B9DA1C255F52095D56568C05B85F56266C76796629A90422F94E9D167F6636761D72C00BD33667B503A32C6C2CF207B99D6B91F047B23AFE6244DF8EB29EFDB8C1DA80BAA2FEE49BCA41900013F1BBE9E6BAD544327'

    test_str='2AF771399A107E313ED0B571945137AEE4A66EF882DD5106BA961BCB16A57CFBB3BEE1F0BA00E2D36EEED1E280EABC40FB2F11823C9C2BF6A852C2568C0871E0F0488879F988A316C113BC059DBBFDE946E36657556EE335773B2DF37A6436725B9C5EFA509150789C174FA610D0B88B9DB5E1BA7FBB01CA9564F3267BF02DAA0B566B3D81215DBCE56D165C87623518B4EBEAF432AFE0191A92FD20B35E9FDA1B09CF20B6BDE295E808F8E8C48D3F09E0323BA394792F4B5DBCE62BE962CAC53FFFAB5CBB9A6739A44473D188DE6301E1FFEC7BAF8A8AE43307D40B8C3CDAB2F4D4E77D866FAEA4C87B702A0020B41480992A7A3C4DF88EEEA69F4C55A428FF1D508A3DEA85DAE79EF51EF3AA3E87577C9BBDD96DDB3512EF3950DB262CFFDCFF2B6B16541E7231C84E0B240982C8025ACE43CBD501F1F59F47F80E2995AAC96BE167F213BAD50D013ADD65F73A8AE662F7546770ED54F7E78C48EA47CC6B0617B8E1813FEBA457CB2FEE8851A104C12DC1FC744CA697584331D33C15E7FECE2E1F92BCC6137908F765FC652B594C83DA1FB1C17EA67DC1080123E7BC4FAE278F5ABC34E99131461DD55510BBCD00E8D5248B818DF8EB9CFA69BAEEEB401B1482D41D9CE7953DC07F9B12602D550F37B6A6AA95CAA9FE400444FDA02F3DD077A741F470A2306927D55AFD1A373AFAF2C00B0B40DCB742CE46E10F9D23EBCB6706069A759DA22824A127A2347E70F9E76D80DDEA970C2176223EC2345B6269E51CA65FD55332E0D35048A0C5DB865E6331DCEE6F98B922DB6874253ADE324263F6D70BF1CE769983ED752D4B54451D0099A4581C5C2EA70152123B0CEFDED2C50C1B9E687F7364119E1F18270BD12EE2663D8AF5660E8E1EC7F7EC454BD64A3D0511A4B8EA7FB6D75E0FB92382A88BA405EBE8765E5A93557B1AF208402725CB6B41C34551846F6AED3CC689F67F7D809DBA0D31E8AF97B2BD4255DAD756746111EBD64EB7AFA60921402B9402E5D604243805265C94066BECB3C19A117D0418ED7FC9C8609015239901B5439EE3FDB7C7FA6960F345314A95122304E87C91C34641C3779FA66A359E351EFF498A933F'

    jstr = String(test_str)
    ret2 = x.deserialdata(emulator, jstr.getBytes(emulator, String("utf-8")))
    #logger.info("Response from deserialdata %s " % ret2)

    logger.info("Exited EMU.")

except UcError as e:
    print("Exit at %x " % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise