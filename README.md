--------------------
# Project code: 北极星



## Notice:
1. Only support Linux platform, development & testing environment are Ubuntu and Debian

## Usage
1. Make sure config.json in same folder,sample
    1. {
    "server":"xxxx",
    "server_port":xxxx,
    "local_port":xxxx,
    "password":"xxxxxx",
    "timeout":600,
    "method": "aes-256-gcm", 
    "local_address":"127.0.0.1",
    "verbose" : 9,
    "prefer_ipv6":"",
    "daemon": "start",
    "ban_count":"9",
    "ban_resume":"10"
    }
2. Start server, sample: 
    1. python server.py
    
3.  Found seriously memory issue related aead cryptor method(including all python sub-version), still in troubleshooting -- ongoing   

Beta 0.4.0(20170819) --ongoing
------------------
1. Change STAGE_CONNECT logic, support read&write remote socket to improve Handshake phase performance
2. Continuously enrich Client-Validation(身份验证) measurement:
    1. Provide Delay close client-socket function when fail validation to prevent Active-DataPackagePuncture Attack -- Failed,Abandon this feature
3. Troubleshooting memory leak issue -- ongoing


Beta 0.3.0(20170813)
------------------
1. Continuously enrich Client-Validation(身份验证) measurement:
    1. Add Ban IP function
        1. Abandon failToBan service, integrate into system to enable Ban IP xxmins if fail to validation exceed x times
        2. Add lib python-iptables lib to manipulate iptables powerful and easily


Beta 0.2.0(20170811)
-------------------
1. Add AEAD encrypto method,support
    1. Classic:
    'aes-128-cfb',
    'aes-192-cfb',
    'aes-256-cfb',
    'aes-128-ofb',
    'aes-192-ofb',
    'aes-256-ofb',
    'aes-128-ctr',
    'aes-192-ctr',
    'aes-256-ctr',
    'aes-128-cfb8',
    'aes-192-cfb8',
    'aes-256-cfb8',
    'aes-128-cfb1',
    'aes-192-cfb1',
    'aes-256-cfb1',
    'bf-cfb',
    'camellia-128-cfb',
    'camellia-192-cfb',
    'camellia-256-cfb',
    'cast5-cfb',
    'des-cfb',
    'idea-cfb',
    'rc2-cfb',
    'rc4',
    'seed-cfb',
    2. AEAD: iv_len = salt_len = key_len
    'aes-128-gcm',
    'aes-192-gcm',
    'aes-256-gcm',
    'aes-128-ocb',
    'aes-192-ocb',
    'aes-256-ocb',
2. Programm robust enhanced and fix a memory leak issue
3. Re-org log writing



Beta 0.1.0(20170808)
-----------
1. Initial version, re-design the original code to handle all stage data more flexiable
   1. Centralize state machine scenario in Module clientStateControl 
   2. For more easily manuplate data,Spilt data stage-handler to 4 Module
