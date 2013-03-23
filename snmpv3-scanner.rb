#!/usr/bin/ruby
require 'openssl'
require 'socket'

# SNMP datatypes

INTEGER                 = "\x02"
OCTET_STRING            = "\x04"
NULL                    = "\x05"
OBJECT_IDENTIFIER       = "\x06"
SEQUENCE                = "\x30"

# msgFlags

MSG_FLAGS_NOAUTHNOPRIV  = "\x00"  # noAuthNoPriv
MSG_FLAGS_AUTH          = "\x01"  # authFlag
MSG_FLAGS_PRIV          = "\x02"  # privFlag
MSG_FLAGS_REPORTABLE    = "\x04"  # reportableFlag

# SNMPv3 defaults
MSG_ID                  = "\x01"
MSG_MAX_SIZE            = "\x20\x00"    # 8192
MSG_SECURITY_MODEL      = "\x03"        # usmSecurityModel

class Password_to_key_md5
        require 'inline'

        inline do |builder|
                # Generate an MD5 Sum as defined by RFC3414
                builder.c <<-EOC
                #include <sys/types.h>
                #include <md5.h>

                void to_md5(
                        u_char *password,    /* IN */
                        u_int   passwordlen, /* IN */
                        u_char *engineID,    /* IN  - pointer to snmpEngineID  */
                        u_int   engineLength,/* IN  - length of snmpEngineID */
                        u_char *key)         /* OUT - pointer to caller 16-octet buffer */
                {
                        MD5_CTX     MD;
                        u_char     *cp, password_buf[64];
                        u_long      password_index = 0;
                        u_long      count = 0, i;

                        MD5Init (&MD);   /* initialize MD5 */

                        /**********************************************/
                        /* Use while loop until we've done 1 Megabyte */
                        /**********************************************/
                        while (count < 1048576) {
                                cp = password_buf;
                                for (i = 0; i < 64; i++) {
                                        /*************************************************/
                                        /* Take the next octet of the password, wrapping */
                                        /* to the beginning of the password as necessary.*/
                                        /*************************************************/
                                        *cp++ = password[password_index++ % passwordlen];
                                }
                                MD5Update (&MD, password_buf, 64);
                                count += 64;
                        }
                        MD5Final (key, &MD);          /* tell MD5 we're done */

                        /*****************************************************/
                        /* Now localize the key with the engineID and pass   */
                        /* through MD5 to produce final key                  */
                        /* May want to ensure that engineLength <= 32,       */
                        /* otherwise need to use a buffer larger than 64     */
                        /*****************************************************/
                        memcpy(password_buf, key, 16);
                        memcpy(password_buf+16, engineID, engineLength);
                        memcpy(password_buf+16+engineLength, key, 16);

                        MD5Init(&MD);
                        MD5Update(&MD, password_buf, 32+engineLength);
                        MD5Final(key, &MD);
                        return;
                }
                EOC
        end
end

def create_probe_snmp3(msgFlags, userName, authPass, privPass, msgAuthEngineID)
        msgAuthEngineBoots = "0"
        msgAuthEngineTime = "0"
        msgAuthParam = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        msgPrivParam = ""

        digest = Password_to_key_md5.new

        digest.to_md5(authPass, authPass.length, msgAuthEngineID, msgAuthEngineID.length, msgAuthParam)

        msgGlobalData =
                INTEGER + [MSG_ID.length].pack('C') + MSG_ID +
                INTEGER + [MSG_MAX_SIZE.length].pack('C') + MSG_MAX_SIZE +
                OCTET_STRING + [msgFlags.length].pack('C') + msgFlags +
                INTEGER + [MSG_SECURITY_MODEL.length].pack('C') + MSG_SECURITY_MODEL
        msgGlobalHead = SEQUENCE + [msgGlobalData.length].pack('C')

        msgSecurityParameters   =
                OCTET_STRING + [msgAuthEngineID.length].pack('C') + msgAuthEngineID +
                INTEGER + [msgAuthEngineBoots.length].pack('C') + msgAuthEngineBoots +
                INTEGER + [msgAuthEngineTime.length].pack('C') + msgAuthEngineTime +
                OCTET_STRING + [userName.length].pack('C') + userName +
                OCTET_STRING + [msgAuthParam.length].pack('C') + msgAuthParam +
                OCTET_STRING + [msgPrivParam.length].pack('C') + msgPrivParam
        msgSecurityHead         =
                OCTET_STRING + [msgSecurityParameters.length + 2].pack('C') +
                SEQUENCE + [msgSecurityParameters.length].pack('C')

        pdu =
                "\x30\x12\x04\x00\x04\x00\xa0\x0c\x02\x02\x13\x89\x02\x01" +
                "\x00\x02\x01\x00\x30\x00"

        msg = msgGlobalHead + msgGlobalData + msgSecurityHead + msgSecurityParameters + pdu

        snmpHead = "\x30" + [msg.length].pack('C')
        msgVersion = "\x02\x01\x03"
        puts "Msg length " + msg.length.to_s
        snmp = snmpHead + msgVersion + msg
        snmp
end

def parse_reply(pkt)
        return if not pkt[1]

#       if(pkt[1] =~ /^::ffff:/)
#               pkt[1] = pkt[1].sub(/^::ffff:/, '')
#       end

        asn1 = OpenSSL::ASN1.decode(pkt) rescue nil
        if(! asn1)
                puts "Not ASN encoded data"
                return
        end

        msgVersion = asn1.value[0]
        msgGlobalData = asn1.value[1]

        # The usmSecurityParameter is an Octet String whose value is a BER encoded ASN1data class, so it must be unpacked
        msgSecurityParameter = OpenSSL::ASN1.decode(asn1.value[2].value)
        msgAuthoritativeEngineID = msgSecurityParameter.value[0].value

        msgData = asn1.value[3]
        contextEngineID = msgData.value[0]
        contextName = msgData.value[1]

        pdu = msgData.value[2]
        requestId = pdu.value[0]
        errorStatus = pdu.value[1]
        errorIndex = pdu.value[2]
        varBind = pdu.value[3]

        var = varBind.value[0]
        oid = var.value[0]
        val = var.value[1]

        snmpResult = {  "msgAuthoritativeEngineID"      => msgAuthoritativeEngineID,
                        "contextEngineID"       => contextEngineID,
                        "errorStatus"           => errorStatus,
                        "oid"                   => oid,
                        "val"                   => val,
                }

        snmpResult
end

rhost = ARGV[1]

udp_socket = UDPSocket.new

data = create_probe_snmp3(MSG_FLAGS_REPORTABLE, "", "", "", "")

udp_socket.bind("127.0.0.1", 4913)

udp_socket.send(data, 0, rhost, 161)

ret, sender = udp_socket.recvfrom(65535)

snmpReturn = parse_reply(ret)

data = create_probe_snmp3((MSG_FLAGS_REPORTABLE + MSG_FLAGS_AUTH), "authOnlyUser", "password", "", snmpReturn["msgAuthoritativeEngineID"])

udp_socket.send(data, 0, rhost, 161)

ret, sender = udp_socket.recvfrom(65535)

snmpReturn = parse_reply(ret)

puts snmpReturn
