# nxos-acl-parser
Provides a script for parsing Cisco NX-OS Access Control List (ACL) rules into a CSV file. 

Do note that this parser is not exhaustive. Special ACL scenarios may fail. Additionally, IPv6 ACLs are currently not taken into consideration.

## Input
Currently the script takes a singular access list in the following format as input:

```
IP access list ACL_NAME
  10 remark FIRST_REMARK
  20 permit ospf any any
  30 permit udp 10.0.0.0/22 range 5000 10000 host 1.1.1.1 range 1023 1025
  40 permit tcp host 11.0.0.1 range 5000 10000 14.0.0.0/22 gt 1023 established
  50 permit tcp 12.0.0.0/22 gt 1023 10.0.0.0/8 range 6620 6629 established
  60 remark SECOND_REMARK
  70 permit tcp 160.0.0.0/22 gt 1023 10.254.128.0/24 eq 9389
```

## Output
Output is directly sent directly to a CSV file. 
```
acl_name,acl_remark,seq_number,acl_action,acl_proto,src_type,src_ip,src_operator,src_port_begin,src_port_end,dst_type,dst_ip,dst_operator,dst_port_begin,dst_port_end,acl_state
ACL_NAME,FIRST_REMARK,10,remark,,,,,,,,,,,,
ACL_NAME,FIRST_REMARK,20,permit,ospf,network,any,,,,network,any,,,,
ACL_NAME,FIRST_REMARK,30,permit,udp,network,10.0.0.0/22,range,5000,10000,host,1.1.1.1,range,1023,1025
ACL_NAME,FIRST_REMARK,40,permit,tcp,host,11.0.0.0/22,range,5000,10000,network,14.0.0.0/22,gt,1023,,established
ACL_NAME,FIRST_REMARK,50,permit,tcp,network,12.0.0.0/22,gt,1023,,network,10.0.0.0/8,range,6620,6629,established
ACL_NAME,SECOND_REMARK,60,remark,,,,,,,,,,,,
ACL_NAME,SECOND_REMARK,70,permit,tcp,network,160.0.0.0/22,gt,1023,,network,10.254.128.0/24,eq,9389,,
```
