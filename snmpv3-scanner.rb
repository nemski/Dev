#!/usr/bin/ruby
require 'openssl'
require 'socket'

class String
  def ^( other )
    b1 = self.unpack("C*")
    b2 = other.unpack("C*")
    longest = [b1.length,b2.length].max
    b1 = [0]*(longest-b1.length) + b1
    b2 = [0]*(longest-b2.length) + b2
    b1.zip(b2).map{ |a,b| a^b }.pack("C*")
  end
end

class OpenSSL::Digest::MD5
# => A Ruby implementation of http://tools.ietf.org/html/rfc3414#appendix-A.2.1
	def usmHMACMD5AuthKey(authPass, msgAuthEngineID)
		@count = 0
		@password_buf = Array.new(64)
		@authPassKey = OpenSSL::Digest::MD5.new

		until @count >= 1048576 do
			@authPassKey << @password_buf.each_with_index.map{ |el,idx| authPass[idx % authPass.length] }.join
			@count += 64
		end

		@password_buf = [(@authPassKey.digest.unpack('C*') + msgAuthEngineID.unpack('C*') + @authPassKey.digest.unpack('C*')).pack('C*')]

		self << @password_buf.join
		self.digest
	end

# => http://tools.ietf.org/html/rfc3414#section-6.3.1
	def usmHMACMD5AuthProtocol(authKey, wholeMsg)
		@extendedAuthKey = (authKey.unpack('C*') + ["\x00" * 48].join.unpack('C*')).pack('C*')
		@IPAD = ["\x36" * 64].join
		@K1 = @extendedAuthKey ^ @IPAD
		@OPAD = ["\x5C" * 64].join
		@K2 = @extendedAuthKey ^ @OPAD
		@MACmd5 = OpenSSL::Digest::MD5.new
		@MACmd5 << (@K1.unpack('C*') + wholeMsg.unpack('C*')).pack('C*')
		@MAC = @MACmd5.digest
		self << (@K2.unpack('C*') + @MAC.unpack('C*')).pack('C*')
		self.digest[0, 12]
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

def create_probe_snmp3(msgFlags, userName, authPass, privPass, msgAuthEngineID, msgAuthEngineBoots, msgAuthEngineTime)
		msgPrivParam = ""
		msgAuthParam = ["\x00" * 12].join

		pdu =
			OCTET_STRING + [msgAuthEngineID.length].pack('C') + msgAuthEngineID +
			"\x04\x00\xa0\x0e\x02\x04\x0e\xf0" + "\xee\x8f\x02\x01\x00\x02\x01\x00" +
			"\x30\x00"
		pduHead = SEQUENCE + [pdu.length].pack('C')

		msgGlobalData =
				INTEGER + [MSG_ID.length].pack('C') + MSG_ID +
				INTEGER + [MSG_MAX_SIZE.length].pack('C') + MSG_MAX_SIZE +
				OCTET_STRING + [msgFlags.length].pack('C') + msgFlags +
				INTEGER + [MSG_SECURITY_MODEL.length].pack('C') + MSG_SECURITY_MODEL
		msgGlobalHead = SEQUENCE + [msgGlobalData.length].pack('C')

		msgSecurityParameters   =
				OCTET_STRING + [msgAuthEngineID.length].pack('C') + msgAuthEngineID +
				INTEGER + [[msgAuthEngineBoots].pack('N').length].pack('C') + [msgAuthEngineBoots].pack('N') +
				INTEGER + [[msgAuthEngineBoots].pack('N').length].pack('C') + [msgAuthEngineTime].pack('N') +
				OCTET_STRING + [userName.length].pack('C') + userName +
				OCTET_STRING + [msgAuthParam.length].pack('C') + msgAuthParam +
				OCTET_STRING + [msgPrivParam.length].pack('C') + msgPrivParam
		msgSecurityHead         =
				OCTET_STRING + [msgSecurityParameters.length + 2].pack('C') +
				SEQUENCE + [msgSecurityParameters.length].pack('C')

#		pdu =
#				"\x30\x12\x04\x00\x04\x00\xa0\x0c\x02\x02\x13\x89\x02\x01" +
#				"\x00\x02\x01\x00\x30\x00"

		msgVersion = "\x02\x01\x03"

		msg = msgVersion + msgGlobalHead + msgGlobalData + msgSecurityHead + msgSecurityParameters + pduHead + pdu

		snmpHead = SEQUENCE + [msg.length].pack('C')
		puts "Msg length " + msg.length.to_s
		snmpMsg = snmpHead + msg

		if authPass.length > 0
			auth = OpenSSL::Digest::MD5.new
			authKey = auth.usmHMACMD5AuthKey(authPass, msgAuthEngineID)
			msg = OpenSSL::Digest::MD5.new
			msgAuthParam = msg.usmHMACMD5AuthProtocol(authKey, snmpMsg)

			# Now we have generated msgAuthParam we need to pack our packet again with the 
			msgSecurityParameters   =
				OCTET_STRING + [msgAuthEngineID.length].pack('C') + msgAuthEngineID +
				INTEGER + [[msgAuthEngineBoots].pack('N').length].pack('C') + [msgAuthEngineBoots].pack('N') +
				INTEGER + [[msgAuthEngineBoots].pack('N').length].pack('C') + [msgAuthEngineTime].pack('N') +
				OCTET_STRING + [userName.length].pack('C') + userName +
				OCTET_STRING + [msgAuthParam.length].pack('C') + msgAuthParam +
				OCTET_STRING + [msgPrivParam.length].pack('C') + msgPrivParam

			msg = msgVersion + msgGlobalHead + msgGlobalData + msgSecurityHead + msgSecurityParameters + pduHead + pdu

			snmpMsg = snmpHead + msg
		end

		snmpMsg
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
		msgAuthoritiveEngineBoots = msgSecurityParameter.value[1].value.to_i
		msgAuthoritiveEngineTime = msgSecurityParameter.value[2].value.to_i

		msgData = asn1.value[3]
		contextEngineID = msgData.value[0]
		contextName = msgData.value[1]

		pdu = msgData.value[2]
		requestId = pdu.value[0]
		errorStatus = pdu.value[1]
		errorIndex = pdu.value[2]
		varBind = pdu.value[3]

		if varBind
			var = varBind.value[0]
			if var
				oid = var.value[0]
				val = var.value[1]
			end
		end

		snmpResult = {  "msgAuthEngineID"		=> msgAuthoritativeEngineID,
						"msgAuthEngineBoots"	=> msgAuthoritiveEngineBoots,
						"msgAuthEngineTime"		=> msgAuthoritiveEngineTime,
						"contextEngineID"       => contextEngineID,
						"errorStatus"           => errorStatus,
						"oid"                   => oid,
						"val"                   => val,
				}

		snmpResult
end

rhost = ARGV[1]

udp_socket = UDPSocket.new

data = create_probe_snmp3(MSG_FLAGS_REPORTABLE, "", "", "", "", 0, 0)

udp_socket.bind("127.0.0.1", 4913)

udp_socket.send(data, 0, rhost, 161)

ret, sender = udp_socket.recvfrom(65535)

snmpReturn = parse_reply(ret)

puts snmpReturn

data = create_probe_snmp3([MSG_FLAGS_REPORTABLE.unpack('H*').join.to_i +
MSG_FLAGS_AUTH.unpack('H*').join.to_i].pack('C'), "authOnlyUser", "password",
"", snmpReturn["msgAuthEngineID"], snmpReturn["msgAuthEngineBoots"],
snmpReturn["msgAuthEngineTime"])

udp_socket.send(data, 0, rhost, 161)

ret, sender = udp_socket.recvfrom(65535)

snmpReturn = parse_reply(ret)

puts snmpReturn
