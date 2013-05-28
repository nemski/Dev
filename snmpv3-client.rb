#!/usr/bin/ruby
require 'openssl'
require 'socket'

SALTLSB = Random.new.bytes(4)

class String
# Bitwise XOR operator for the String class
	def ^( other )
		b1 = self.unpack("C*")
		if ! other
		return b1
	end
	b2 = other.unpack("C*")
	longest = [b1.length,b2.length].max
	b1 = [0]*(longest-b1.length) + b1
	b2 = [0]*(longest-b2.length) + b2
	b1.zip(b2).map{ |a,b| a^b }.pack("C*")
  end
end

class OpenSSL::Digest::SHA1_USM < OpenSSL::Digest::SHA1
# => Ruby implementation of http://tools.ietf.org/html/rfc3414#appendix-A.2.2
	def usmHMACSHAAuthKey(authPass, msgAuthEngineID)
		@authPass, @msgAuthEngineID = authPass, msgAuthEngineID
		@count = 0
		@password_buf = Array.new(64)
		@digest_buf = Array.new(72)
		@authPassKey = OpenSSL::Digest::SHA1.new

		until @count >= 1048576 do
			@authPassKey << @password_buf.each_with_index.map{ |el,idx| @authPass[idx % @authPass.length, 1] }.join
			@count += 64
		end

		self << @authPassKey.digest
		self << @msgAuthEngineID
		self << @authPassKey.digest
		self.digest
	end

# => http://tools.ietf.org/html/rfc3414#section-7.3.1
	def usmHMACSHAAuthProtocol(authKey, snmpMsg)
		@authKey, @snmpMsg = authKey, snmpMsg
		@extendedAuthKey = @authKey
		@extendedAuthKey << ["\x00" * 44].join
		@IPAD = ["\x36" * 64].join
		@K1 = @extendedAuthKey ^ @IPAD
		@OPAD = ["\x5C" * 64].join
		@K2 = @extendedAuthKey ^ @OPAD
		@shaMAC = OpenSSL::Digest::SHA1.new
		@shaMAC << @K1
		@shaMAC << @snmpMsg
		@MAC = @shaMAC.digest
		self << @K2
		self << @MAC
		self.digest[0, 12]
	end
end

class OpenSSL::Digest::MD5_USM < OpenSSL::Digest::MD5
# => A Ruby implementation of http://tools.ietf.org/html/rfc3414#appendix-A.2.1
	def usmHMACMD5AuthKey(authPass, msgAuthEngineID)
		@authPass, @msgAuthEngineID = authPass, msgAuthEngineID
		@count = 0
		@password_buf = Array.new(64)
		@authPassKey = OpenSSL::Digest::MD5.new

		until @count >= 1048576 do
			@authPassKey << @password_buf.each_with_index.map{ |el,idx| @authPass[idx % @authPass.length] }.join
			@count += 64
		end

		self << @authPassKey.digest
		self << @msgAuthEngineID
		self << @authPassKey.digest
		self.digest
	end

# => http://tools.ietf.org/html/rfc3414#section-6.3.1
	def usmHMACMD5AuthProtocol(authKey, wholeMsg)
		@authKey, @wholeMsg = authKey, wholeMsg
		@extendedAuthKey = @authKey
		@extendedAuthKey << ["\x00" * 48].join
		@IPAD = ["\x36" * 64].join
		@K1 = @extendedAuthKey ^ @IPAD
		@OPAD = ["\x5C" * 64].join
		@K2 = @extendedAuthKey ^ @OPAD
		@md5MAC = OpenSSL::Digest::MD5.new
		@md5MAC << @K1
		@md5MAC << @wholeMsg
		@MAC = @md5MAC.digest
		self << @K2
		self << @MAC
		self.digest[0, 12]
	end
end

class OpenSSL::Cipher::DES_USM < OpenSSL::Cipher::DES
# => http://tools.ietf.org/html/rfc3414#section-8.1.1.1
	def usmDESPrivKey(privPass, msgAuthEngineBoots)
		@privPass, @msgAuthEngineBoots = privPass, msgAuthEngineBoots
		if @msgAuthEngineBoots.to_s.size < 4
			@tmp = @msgAuthEngineBoots
			@msgAuthEngineBoots = NULL * (4 - @tmp.to_s.size) 
			@msgAuthEngineBoots << [@tmp.to_s].pack('H*')
		end

# => desKey is has "the Least Significant Bit in each octet disregarded."
		@bitstring = @privPass.unpack('B*').join.split(//)
		@octets = @bitstring.length / 8
		while @octets > 0 do
			@bitstring.delete_at((@octets * 8) - 1)
			@octets -= 1
		end
		@desKey = "\x00"
		@desKey << [@bitstring.join].pack('B*')
		# Where in RFC does it need to eb padded? is this implementation dependant, can't find source code but it fails with the 7-bytes (56bit) 
		

		@preIV = @privPass[4, 4]
		@salt = @msgAuthEngineBoots[0,4]
		@salt << SALTLSB.to_s
		@iv = (@salt ^ @preIV)
		[@iv, @desKey, @salt]
	end
# => http://tools.ietf.org/html/rfc3414#section-8.1.1.2
	def usmDESPrivProtocol(cryptKey, iv, scopedPDU)
		self.encrypt
		self.key = cryptKey
		self.iv = iv
		cipherText = self.update(scopedPDU) + self.final
		cipherText
	end
end

# SNMP datatypes

INTEGER				 = "\x02"
OCTET_STRING			= "\x04"
NULL					= "\x00"
OBJECT_IDENTIFIER	   = "\x06"
SEQUENCE				= "\x30"

# msgFlags

MSG_FLAGS_NOAUTHNOPRIV  = 0  # noAuthNoPriv
MSG_FLAGS_AUTH		  = 1  # authFlag
MSG_FLAGS_PRIV		  = 2  # privFlag
MSG_FLAGS_REPORTABLE	= 4  # reportableFlag

# SNMPv3 defaults
MSG_ID				  = 56219466
MSG_MAX_SIZE			= 65507
MSG_SECURITY_MODEL	  = 3	   	# usmSecurityModel
MSG_VERSION = 3

def create_probe_snmp3(msgFlags, userName, authPass, authProto, privPass, privProto, msgAuthEngineID, msgAuthEngineBoots, msgAuthEngineTime)
	msgPrivParam = ""
	msgAuthParam = ["\x00" * 12].join

	pdu = OpenSSL::ASN1::OctetString(msgAuthEngineID).to_der
	pdu << "\x04\x00\xa1\x1b\x02\x04\x07\xcf\xc6\xa1\x02\x01\x00\x02\x01\x00"
	pdu << "\x30\x0d\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x05\x00"
		

	scopedPDU = OpenSSL::ASN1::Sequence([pdu])

	# Privacy
	if (msgFlags.to_i == 3 || msgFlags.to_i == 7)
		if((privProto <=> "DES") == 0)
			crypt = OpenSSL::Cipher::DES_USM.new("CBC")
			iv, desKey, msgPrivParam = crypt.usmDESPrivKey(privPass, msgAuthEngineBoots)
			crypt = OpenSSL::Cipher::DES_USM.new("CBC")
			encryptedPDU = crypt.usmDESPrivProtocol(desKey, iv, scopedPDU.to_der)
		end

		puts "msgAuthEngineBoots: " + msgAuthEngineBoots.to_s
		puts "msgPrivParam: " + msgPrivParam.unpack('H*').join
		puts "encryptedPDU: " + encryptedPDU.unpack('H*').join
		puts "iv: " + iv.unpack('H*').join
		puts "desKey: " + desKey.unpack('H*').join

		scopedPDU = OpenSSL::ASN1::OctetString(encryptedPDU)
	end

	# Authorization
	if msgFlags.to_i.odd?
		snmpMsg = gen_snmpMsg(msgFlags, msgAuthEngineID, msgAuthEngineBoots, msgAuthEngineTime, userName, msgAuthParam, msgPrivParam, scopedPDU)
		if ((authProto <=> "MD5") == 0)
			auth = OpenSSL::Digest::MD5_USM.new
			authKey = auth.usmHMACMD5AuthKey(authPass, msgAuthEngineID)
			msg = OpenSSL::Digest::MD5_USM.new
			msgAuthParam = msg.usmHMACMD5AuthProtocol(authKey, snmpMsg)
		elsif ((authProto <=> "SHA") == 0)
			auth = OpenSSL::Digest::SHA1_USM.new
			authKey = auth.usmHMACSHAAuthKey(authPass, msgAuthEngineID)
			msg = OpenSSL::Digest::SHA1_USM.new
			msgAuthParam = msg.usmHMACSHAAuthProtocol(authKey, snmpMsg)
		else
			puts "Authentication protocol must be MD5 or SHA"
			return nil
		end

		puts "msgAuthParam: " + msgAuthParam.unpack('H*').join
	end
	
	snmpMsg = gen_snmpMsg(msgFlags, msgAuthEngineID, msgAuthEngineBoots, msgAuthEngineTime, userName,
				msgAuthParam, msgPrivParam, scopedPDU)
	puts "Msg length " + snmpMsg.length.to_s
	snmpMsg
end

def gen_snmpMsg(msgFlags, msgAuthEngineID, msgAuthEngineBoots, msgAuthEngineTime, userName, msgAuthParam, msgPrivParam, scopedPDU)

	msgGlobalData = [
		OpenSSL::ASN1::Integer.new(MSG_ID),
		OpenSSL::ASN1::Integer.new(MSG_MAX_SIZE),
		OpenSSL::ASN1::OctetString.new([msgFlags].pack('h*')),
		OpenSSL::ASN1::Integer.new(MSG_SECURITY_MODEL),
	]

	msgSecurityParameters   = [
		OpenSSL::ASN1::OctetString(msgAuthEngineID),
		OpenSSL::ASN1::Integer(msgAuthEngineBoots),
		OpenSSL::ASN1::Integer(msgAuthEngineTime),
		OpenSSL::ASN1::OctetString(userName),
		OpenSSL::ASN1::OctetString(msgAuthParam),
		OpenSSL::ASN1::OctetString(msgPrivParam),
	]

	msg = [ OpenSSL::ASN1::Integer(MSG_VERSION), OpenSSL::ASN1::Sequence(msgGlobalData), 
	OpenSSL::ASN1::OctetString(OpenSSL::ASN1::Sequence(msgSecurityParameters).to_der), scopedPDU ]
	
	wholeMsg = OpenSSL::ASN1::Sequence(msg).to_der

	wholeMsg
end


def parse_reply(pkt)
		return if not pkt[1]

		asn1 = OpenSSL::ASN1.decode(pkt) rescue nil
		if(! asn1)
				puts "Not ASN encoded data"
				return
		end

		msgVersion = asn1.value[0]
		msgGlobalData = asn1.value[1]

		# The usmSecurityParameter is an Octet String whose value is a BER encoded ASN1data class, so it must be unpacked
		msgSecurityParameter = OpenSSL::ASN1.decode(asn1.value[2].value)
		msgAuthoritiveEngineID = msgSecurityParameter.value[0].value
		msgAuthoritiveEngineBoots = msgSecurityParameter.value[1].value.to_i
		msgAuthoritiveEngineTime = msgSecurityParameter.value[2].value.to_i
		puts "msgAuthoritiveEngineTime: #{msgAuthoritiveEngineTime}"

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

		snmpResult = {  "msgAuthEngineID"		=> msgAuthoritiveEngineID,
						"msgAuthEngineBoots"	=> msgAuthoritiveEngineBoots,
						"msgAuthEngineTime"		=> msgAuthoritiveEngineTime,
						"contextEngineID"	   => contextEngineID,
						"errorStatus"		   => errorStatus,
						"oid"				   => oid,
						"val"				   => val,
				}

		snmpResult
end

rhost = ARGV[1]

udp_socket = UDPSocket.new

# Get our msgAuthEngine* values
data = create_probe_snmp3(MSG_FLAGS_REPORTABLE.to_s, "", "", "", "", "", "", 0, 0)

udp_socket.bind("127.0.0.1", 4913)

udp_socket.send(data, 0, rhost, 161)

ret, sender = udp_socket.recvfrom(65535)

snmpReturn = parse_reply(ret)

puts snmpReturn

data =
	create_probe_snmp3(
		(MSG_FLAGS_REPORTABLE + MSG_FLAGS_AUTH + MSG_FLAGS_PRIV).to_s, 	# msgFlags
		"authPrivUser",																						# user Name
		"password", "MD5",																					# authPass, authProto
		"password", "DES", 																			# privPass, privProto
		snmpReturn["msgAuthEngineID"], snmpReturn["msgAuthEngineBoots"], snmpReturn["msgAuthEngineTime"]	#
	)

udp_socket.send(data, 0, rhost, 161)

ret, sender = udp_socket.recvfrom(65535)

snmpReturn = parse_reply(ret)

puts snmpReturn
