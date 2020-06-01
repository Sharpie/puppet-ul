require 'open3'
require 'puppet/util'

# Generate password hashes for /etc/shadow
#
# This function converts password strings into hashed values suitable
# for use on most *NIX systems. This `pw_hash` implementation is similar
# to the function of the same name from `puppetlabs-stdlib` but uses
# the `openssl passwd` CLI bundled with Puppet and Bolt to overcome the
# limitations of `crypt(3)` on some platforms. This is useful in situations
# such as using `bolt` on macOS to set passwords on remote Linux systems.
#
# @see https://www.openssl.org/docs/man1.1.1/man1/openssl-passwd.html
# @see https://www.man7.org/linux/man-pages/man3/crypt.3.html
# @see https://forge.puppet.com/puppetlabs/stdlib/reference#pw_hash
Puppet::Functions.create_function(:'ul::pw_hash') do
  dispatch :pw_hash do
    param 'String[1]', :password
    param 'Enum["md5", "sha-256", "sha-512"]', :hash_type
    param 'Pattern[/\A[a-zA-Z0-9.\/]+\z/]', :salt
    return_type 'String[1]'
  end

  def pw_hash(password, hash_type, salt)
    hash_arg = case hash_type
               when 'md5'
                 '-1'
               when 'sha-256'
                 '-5'
               when 'sha-512'
                 '-6'
               end

    openssl_bin = find_openssl

    # FIXME: Open3 is probably not safe to use under JRuby.
    #        Should copy stdlib's method for using Java libraries.
    stdout, stderr, status = Open3.capture3(openssl_bin,
                                            'passwd',
                                            hash_arg,
                                            '-salt', salt,
                                            '-stdin',
                                            stdin_data: password)

    if status.success?
      stdout.chomp
    else
      raise '%{command} exited with code %{code}: %{stderr}' %
            {command: openssl_bin,
             code: status.exitstatus,
             stderr: stderr}
    end
  end

  # Return a path to openssl
  #
  # @raise [RuntimeError] if no `openssl` executable can be found
  # @return [String] path to `openssl` executable
  def find_openssl
    openssl_bin = 'openssl' + RbConfig::CONFIG['EXEEXT']

    # First, look for openssl distributed with puppet-agent or bolt packages.
    openssl = File.join(RbConfig::CONFIG['bindir'], openssl_bin)
    # Next, try $PATH
    openssl = Puppet::Util.which(openssl_bin) unless Puppet::FileSystem.executable?(openssl)

    unless Puppet::FileSystem.executable?(openssl)
      raise 'No %{openssl} executable in %{bindir} or PATH' %
            {openssl: openssl_bin,
             bindir: RbConfig::CONFIG['bindir']}
    end

    openssl
  end
end
