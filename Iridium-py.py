from scapy.all import *
import json
import base64
from MT19937_64 import MT19937_64
import parse_proto as pp
import keyboard


def get_packet_id(b_data):
    packet_id = int.from_bytes(b_data[2:4], byteorder="big", signed=False)
    return packet_id


def remove_magic(b_data):  # GetPlayerTokenRsp 只用
    cut = b_data[5]
    b_data = b_data[8 + 2:]
    b_data = b_data[:len(b_data) - 2]
    b_data = b_data[cut:]
    return b_data


def remove_magic1(b_data):
    try:
        cut = b_data[6]
        b_data = remove_magic(b_data)
        return b_data[cut:]
    except IndexError:
        pass  # 特殊包


def parse_proto(pck_id, b_data):
   
    if pck_id == 131:
        data = pp.parse(b_data, get_proto_name_by_id(pck_id))
        i_seed = data['secret_key_seed']
        return i_seed
    else:
        proto_name = get_proto_name_by_id(pck_id)
        if proto_name:
            data = pp.parse(b_data, proto_name)
            if data:
                return data
        else:
            print("获取不到proto名称编号：" + str(pck_id))


def sniff_package(*args):
    piface = ""
    if type(args[0]) == int:
        pkg = sniff(iface=piface, count=args[0], filter="udp port 22102||22101")
        for package in pkg:
            b_data = package[Raw].load
            if get_init_key(b_data, d_keys):
                key = get_init_key(b_data, d_keys)
                b_data = b_data[28:]
                decrypt_data = xor(b_data, key)
                packet_id = get_packet_id(decrypt_data)
                if packet_id == 131:
                    b_data = remove_magic(decrypt_data)
                    i_seed = parse_proto(131, b_data)
                    return i_seed
        print("没抓到诶，是在进门前就运行了吗?")
    else:
        while True:
            if keyboard.is_pressed("q"):
                input("暂停中，输入任意键继续")
            pkg = sniff(iface=piface, count=1, filter="udp port 22102||22101")
            # port = pkg[0].sprintf("%UDP.sport%")
            # if port == "22102" or port == "22101":
            #     print("server", end=" ")
            # else:
            #     print("client", end=" ")

            b_data = pkg[0][Raw].load
            b_data = b_data[28:]
            key = args[0]
            decrypt_data = xor(b_data, key)
            packet_id = get_packet_id(decrypt_data)
            b_data = remove_magic1(decrypt_data)
            if packet_id == 0 or packet_id == 98:
                continue


            proto_name = get_proto_name_by_id(packet_id)
            if proto_name:
                try:
                    data = parse_proto(packet_id, b_data)
                    print(proto_name, data)
                except Exception:
                    pass


def read_keys():
    f = open("Keys.json", "r")
    d_initialKeys = json.load(f)
    return d_initialKeys


def read_packet_id():
    f = open("packetIds.json", "r")
    d_packet_id = json.load(f)
    return d_packet_id


def get_init_key(b_data, keys):
    key_id = int.from_bytes(b_data[28:30], byteorder="big", signed=False)
    possible_key_id = str(key_id ^ 0x4567)
    if possible_key_id in keys.keys():
        key = base64.b64decode(keys[possible_key_id])
        return key
    else:
        return False


def xor(b_data, b_key):
    decrypt_data = b""
    for j in range(len(b_data)):
        decrypt_data += (b_data[j] ^ b_key[j % len(b_key)]).to_bytes(1, byteorder="big", signed=False)
    return decrypt_data


def generate_key(seed):
    first = MT19937_64()
    first.seed(seed)
    gen = MT19937_64()
    gen.seed(first.int64())
    gen.int64()
    key = b""
    for i in range(0, 4096, 8):
        num = gen.int64()
        key += num.to_bytes(8, byteorder="big", signed=False)
    return key


def get_proto_name_by_id(i_id):
    try:
        proto_name = d_pkt_id[str(i_id)]
        return proto_name
    except KeyError:
        return False


d_keys = read_keys()
d_pkt_id = read_packet_id()

seed = sniff_package(6)
new_key = generate_key(seed)
# input()
sniff_package(new_key)

