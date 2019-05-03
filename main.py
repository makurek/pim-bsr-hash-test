import ipaddress
from operator import xor
'''
   Value(G,M,C(i))=
   (1103515245 * ((1103515245 * (G&M)+12345) XOR C(i)) + 12345) mod 2^31
   
   CSR1#sh ip pim rp-hash 239.239.2.1
  RP 12.0.0.2 (?), v2
    Info source: 12.0.0.7 (?), via bootstrap, priority 0, holdtime 150
         Uptime: 1d04h, expires: 00:01:47
  PIMv2 Hash Value (mask 0.0.0.0)
    RP 12.0.0.2, via bootstrap, priority 0, hash value 1936241496

root> show pim rps 239.239.2.1
Instance: PIM.master

239.239.0.0/17
        12.0.0.2        Hash: 1936241496

224.0.0.0/4
        12.0.0.8        Hash: 1638507286

RP selected: 12.0.0.2

   
   TODO: UNIT TESTING
'''

def calc_hash(group, mask, rp):
    hash = (1103515245 * ((1103515245 * (group & mask)+12345) ^ rp) + 12345) % pow(2,31)
    return hash

def convert_ip_to_int(group):
    group_int = 0x0
    octets = group.split('.')
    group_int = group_int | int(octets[0]) << 24
    group_int = group_int | int(octets[1]) << 16
    group_int = group_int | int(octets[2]) << 8
    group_int = group_int | int(octets[3])
    return group_int

rps = ['12.0.0.2', '12.0.0.8']
mask = 0xfffffffc
mcast_net = ipaddress.ip_network('239.239.2.0/24')
d = {}
for rp in rps:
    d[rp] = 0
for group in mcast_net.hosts():
    z = {}
    for rp in rps:
        h = calc_hash(convert_ip_to_int(str(group)), mask, convert_ip_to_int(rp))
        z[rp] = h
    sorted_z = sorted(z, key=z.get)
    d[sorted_z[0]] = d[sorted_z[0]] + 1
print(d)


