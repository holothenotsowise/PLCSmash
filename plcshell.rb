require 'msf/core'

class Metasploit3 < Msf::Auxiliary 
		

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include MSF::Auxiliary::Report

	def initialize
		super(
		 'Name'			=>'Siemens Simatic S7-200 PLC',
                 'Version'             =>'$Version: 1$',
		 'Description'           =>'Gets PLC info and crafts packets',
		 'Author'             =>'Holothenotsowise <holothenotsowise@gmail.com',
		 'License'            =>MSF_LICENSE
		)
                register_options([Opt::RPORT(102)], self.class)
	end

def run_host(ip)
begin
pkt = [		"\x03\x00\x00\x16\x11\xe0\x00\x00"+
		"\x00\x2c\x00\xc1\x02\x06\x00\xc2"+
		"\x02\x06\x00\xc0\x01\x0a",
		"\x03\x00\x00\x07\x02\xf0\x00"
      ]
		connect()

