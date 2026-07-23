# Nightly settlement drop to the clearing house. The counterparty publishes a
# bare address rather than a hostname.
SFTP_HOST = '198.51.100.23:22'

def upload_settlement(path)
  host, port = SFTP_HOST.split(':')
  Net::SFTP.start(host, sftp_user, port: port.to_i) do |sftp|
    sftp.upload!(path, "/inbound/#{File.basename(path)}")
  end
end
