require 'openssl'
require 'socket'

Encoding.default_external = Encoding::ASCII-8BIT
Encoding.default_internal = Encoding::ASCII-8BIT

# DES salt

SALTLSB = Random.new.bytes(4)

# SNMP datatypes

INTEGER                 = "\x02"
OCTET_STRING            = "\x04"
NULL                    = "\x05"
OBJECT_IDENTIFIER       = "\x06"
SEQUENCE                = "\x30"

# msgFlags

MSG_FLAGS_NOAUTHNOPRIV  = 0  # noAuthNoPriv
MSG_FLAGS_AUTH          = 1  # authFlag
MSG_FLAGS_PRIV          = 2  # privFlag
MSG_FLAGS_REPORTABLE    = 4  # reportableFlag

# SNMPv3 defaults
MSG_ID                  = "\x01"
MSG_MAX_SIZE            = "\x00\xFF\xE3"    # 65507
MSG_SECURITY_MODEL      = "\x03"        # usmSecurityModel

class String
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

class OpenSSL::Digest::SHA1
# => Ruby implementation of http://tools.ietf.org/html/rfc3414#appendix-A.2.2
	def usmHMACSHAAuthKey(authPass, msgAuthEngineID)
		@count = 0
		@password_buf = Array.new(64)
		@digest_buf = Array.new(72)
		@authPassKey = OpenSSL::Digest::SHA1.new

		until @count >= 1048576 do
			@authPassKey << @password_buf.each_with_index.map{ |el,idx| authPass[idx % authPass.length] }.join
			@count += 64
		end

		@digest_buf = [(@authPassKey.digest.unpack('C*') + msgAuthEngineID.unpack('C*') + @authPassKey.digest.unpack('C*')).pack('C*')]

		self << @digest_buf.join
		self.digest
	end

# => http://tools.ietf.org/html/rfc3414#section-7.3.1
	def usmHMACSHAAuthProtocol(authKey, wholeMsg)
		@extendedAuthKey = (authKey.unpack('C*') + ["\x00" * 44].join.unpack('C*')).pack('C*')
		@IPAD = ["\x36" * 64].join
		@K1 = @extendedAuthKey ^ @IPAD
		@OPAD = ["\x5C" * 64].join
		@K2 = @extendedAuthKey ^ @OPAD
		@shaMAC = OpenSSL::Digest::SHA1.new
		@shaMAC << (@K1.unpack('C*') + wholeMsg.unpack('C*')).pack('C*')
		@MAC = @shaMAC.digest
		self << (@K2.unpack('C*') + @MAC.unpack('C*')).pack('C*')
		self.digest[0, 12]
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
		@md5MAC = OpenSSL::Digest::MD5.new
		@md5MAC << (@K1.unpack('C*') + wholeMsg.unpack('C*')).pack('C*')
		@MAC = @md5MAC.digest
		self << (@K2.unpack('C*') + @MAC.unpack('C*')).pack('C*')
		self.digest[0, 12]
	end
end

class OpenSSL::Cipher
# => http://tools.ietf.org/html/rfc3414#section-8.1.1.1

	def usmDESPrivKey(privPass, msgAuthEngineBoots)
		if msgAuthEngineBoots.to_s.size < 4
			tmp = msgAuthEngineBoots
			msgAuthEngineBoots = "0" * (4 - tmp.to_s.size) + tmp.to_s
		end

# => desKey is meant to have "the Least Significant Bit in each octet disregarded."
# This is only going to work on a little-endian system
		bitstring = privPass.unpack('B*').to_s.split(//)
		octets = bitstring.length / 8
		while octets > 0 do
			bitstring.delete_at((octets * 8) - 1)
			octets -= 1
		end
		desKey = [bitstring.join].pack('B*')

		@preIV = privPass[8, 16]
		salt = (msgAuthEngineBoots.to_s[0, 4] + SALTLSB.to_s)
		iv = (salt ^ @preIV)
		[iv, desKey, salt]
	end
# => http://tools.ietf.org/html/rfc3414#section-8.1.1.2
	def usmDESPrivProtocol(cryptKey, iv, scopedPDU)
		self.encrypt
		self.key = cryptKey
		self.iv = iv
		self.update(scopedPDU) + self.final
	end
end

class HexString
	def initialize(x)
		[x].pack('C')
	end
end

msgFlags = [MSG_FLAGS_REPORTABLE + MSG_FLAGS_AUTH + MSG_FLAGS_PRIV].pack('C')
userName = "authPrivUser"
authPass = "password"
authProto = "MD5"
privPass = "password"
privProto = "DES"
msgAuthEngineID = "\x80\x00\x1f\x88\x80\xda\xa2\x14\x66\x1b\x11\x7b\x51"
msgAuthEngineBoots = 1
msgAuthEngineTime = 1907128
msgVersion = "\x02\x01\x03"

msgPrivParam = ""
msgAuthParam = ["\x00" * 12].join

pdu =
	OCTET_STRING + [msgAuthEngineID.length].pack('C') + msgAuthEngineID +
	"\x04\x00\xa0\x0e\x02\x04\x0e\xf0" + "\xee\x8f\x02\x01\x00\x02\x01\x00" +
	"\x30\x00"

msgGlobalData =
	INTEGER + [MSG_ID.length].pack('C') + MSG_ID +
	INTEGER + [MSG_MAX_SIZE.length].pack('C') + MSG_MAX_SIZE +
	OCTET_STRING + [msgFlags.length].pack('C') + msgFlags +
	INTEGER + [MSG_SECURITY_MODEL.length].pack('C') + MSG_SECURITY_MODEL
msgGlobalHead = SEQUENCE + [msgGlobalData.length].pack('C')

# Privacy
if (msgFlags.unpack('H*').join.to_i == 3 || msgFlags.unpack('H*').join.to_i == 7)
	if((privProto <=> "DES") == 0)
		scopedPDU = SEQUENCE + [pdu.length].pack('C') + pdu

		crypt = OpenSSL::Cipher::DES.new("CBC")
		iv, desKey, msgPrivParam = crypt.usmDESPrivKey(privPass, msgAuthEngineBoots)
		iv.encoding()
		crypt = OpenSSL::Cipher::DES.new("CBC")
		encryptedPDU = crypt.usmDESPrivProtocol(desKey, iv, scopedPDU)
	end

	puts "msgPrivParam: " + msgPrivParam.unpack('H*').join
	puts "encryptedPDU: " + encryptedPDU.unpack('H*').join
	puts "iv: " + iv.unpack('H*').join
	puts "desKey: " + desKey.unpack('H*').join

	pdu = encryptedPDU
end

# Authorization
if msgFlags.unpack('H*').join.to_i.odd?
	if ((authProto <=> "MD5") == 0)
		auth = OpenSSL::Digest::MD5.new
		authKey = auth.usmHMACMD5AuthKey(authPass, msgAuthEngineID)
		msg = OpenSSL::Digest::MD5.new
		msgAuthParam = msg.usmHMACMD5AuthProtocol(authKey, snmpMsg)
	elsif ((authProto <=> "SHA") == 0)
		auth = OpenSSL::Digest::SHA1.new
		authKey = auth.usmHMACSHAAuthKey(authPass, msgAuthEngineID)
		msg = OpenSSL::Digest::SHA1.new
		msgAuthParam = msg.usmHMACSHAAuthProtocol(authKey, snmpMsg)
	else
		puts "Authentication protocol must be MD5 or SHA"
		return nil
	end

end

msgSecurityParameters   =
	OCTET_STRING + [msgAuthEngineID.length].pack('C') + msgAuthEngineID +
	INTEGER + [[msgAuthEngineBoots].pack('w').length].pack('C') + [msgAuthEngineBoots].pack('w') +
	INTEGER + [[msgAuthEngineBoots].pack('w').length].pack('C') + [msgAuthEngineTime].pack('w') +
	OCTET_STRING + [userName.length].pack('C') + userName +
	OCTET_STRING + [msgAuthParam.length].pack('C') + msgAuthParam +
	OCTET_STRING + [msgPrivParam.length].pack('C') + msgPrivParam
msgSecurityHead         =
	OCTET_STRING + [msgSecurityParameters.length + 2].pack('C') +
	SEQUENCE + [msgSecurityParameters.length].pack('C')

pduHead = SEQUENCE + [pdu.length].pack('C')

msg = msgVersion + msgGlobalHead + msgGlobalData + msgSecurityHead + msgSecurityParameters + pduHead + pdu

if encryptedPDU
	snmpHead = SEQUENCE + [msg.length - msgPrivParam.length].pack('C') + [msg.length].pack('C')
else
	snmpHead = SEQUENCE + [msg.length].pack('C')
end
puts "Msg length " + msg.length.to_s
snmpMsg = snmpHead + msg