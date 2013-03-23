#!/usr/bin/ruby
require 'openssl'
require 'socket'

class OpenSSL::Digest::MD5
	# A Ruby implementation of http://tools.ietf.org/html/rfc3414#appendix-A.2.1
	def usmHMACMD5AuthKey(authPass, msgAuthEngineID)
		@count = 0
		@password_buf = Array.new(64)
		@password_index = 0

			begin
				@password_index += 1
				@password_buf.each do |i|
					i = authPass[@password_index % authPass.length]
				end

				self << @password_buf.to_s
				@count += 64
			end until @count >= 1048576

			@password_buf = "self.digest + msgAuthEngineID + self.digest"

			self << @password_buf.to_s
			self.digest
	end

	def usmHMACMD5AuthProtocol(authKey, wholeMsg)
=begin
   2) From the secret authKey, two keys K1 and K2 are derived:

      a) extend the authKey to 64 octets by appending 48 zero octets;
         save it as extendedAuthKey

      b) obtain IPAD by replicating the octet 0x36 64 times;

      c) obtain K1 by XORing extendedAuthKey with IPAD;

      d) obtain OPAD by replicating the octet 0x5C 64 times;

      e) obtain K2 by XORing extendedAuthKey with OPAD.

   3) Prepend K1 to the wholeMsg and calculate MD5 digest over it
      according to [RFC1321].

   4) Prepend K2 to the result of the step 4 and calculate MD5 digest
      over it according to [RFC1321].  Take the first 12 octets of the
      final digest - this is Message Authentication Code (MAC).
=end

	end
end

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

def create_probe_snmp3(msgFlags, userName, authPass, privPass, msgAuthEngineID)
		msgAuthEngineBoots = "0"
		msgAuthEngineTime = "0"
		msgPrivParam = ""
		msgAuthParam = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

		if authPass.length > 0
			authKey = OpenSSL::Digest::MD5.new
			authKey.usmHMACMD5AuthKey(authPass, msgAuthEngineID)
		end

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

#		pdu =
#				"\x30\x12\x04\x00\x04\x00\xa0\x0c\x02\x02\x13\x89\x02\x01" +
#				"\x00\x02\x01\x00\x30\x00"
		pdu =
				"\x30\x14\x04\x00\x04\x00\xa0\x0e" + "\x02\x04\x0e\xf0\xee\x8f\x02\x01" +
				"\x00\x02\x01\x00\x30\x00"

		msgVersion = "\x02\x01\x03"

		msg = msgVersion + msgGlobalHead + msgGlobalData + msgSecurityHead + msgSecurityParameters + pdu

		snmpHead = SEQUENCE + [msg.length].pack('C')
		puts "Msg length " + msg.length.to_s
		snmp = snmpHead + msg
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

data = create_probe_snmp3([MSG_FLAGS_REPORTABLE.unpack('H*').join.to_i + MSG_FLAGS_AUTH.unpack('H*').join.to_i].pack('C'), "authOnlyUser", "password", "", snmpReturn["msgAuthoritativeEngineID"])

udp_socket.send(data, 0, rhost, 161)

ret, sender = udp_socket.recvfrom(65535)

snmpReturn = parse_reply(ret)

puts snmpReturn
