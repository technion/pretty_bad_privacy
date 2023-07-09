#!/usr/bin/env ruby

require 'openssl'

def derive_subkey(extension, key)
  raise "Invalid key length" if key.size != 32
  raise "Invalid extension length" if extension.size !=16
  puts "Here with #{extension}"
  key.freeze # Just to be paranoid

  # Bigger Ruby rabbit hole than it should have been.
  # Docs have AES in caps, but that only works for AES-128 ???
  cipher = OpenSSL::Cipher.new('aes-256-cbc')
  cipher.encrypt
  cipher.iv = "\x0"*16 # Hard code. Do not allow to be messed with..
  cipher.key = key
  encrypted0 = cipher.update("#{extension}doing b0\x01") + cipher.final
  b0 = encrypted0[encrypted0.size-16..encrypted0.size-1]

  cipher = OpenSSL::Cipher.new('aes-256-cbc')
  cipher.encrypt
  cipher.iv = "\x0"*16 # Hard code. Do not allow to be messed with.
  cipher.key = key
  encrypted1 = cipher.update("#{encrypted0}doing b1\x02") + cipher.final
  b1 = encrypted1[encrypted1.size-16..encrypted1.size-1]

  cipher = OpenSSL::Cipher.new('aes-256-cbc')
  cipher.encrypt
  cipher.iv = "\x0"*16 # Hard code. Do not allow to be messed with.
  cipher.key = key
  encrypted2 = cipher.update("#{encrypted1}doing commitment\x03") + cipher.final
  c0 = encrypted2[encrypted2.size-16..encrypted2.size-1]

  [b0 + b1, c0]
end

K = "YELLOW SUBMARINE"*2
E = "E"*16

subkey, commit = derive_subkey(E, K)
puts subkey.size
puts subkey.unpack("H*").join

puts commit.size
puts commit.unpack("H*").join
