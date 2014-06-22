#!/usr/bin/env ruby

# This script provides a dynamic dns functionality
# for domain names hosted at Amazon Route 53 DNS service
# Launch this with cron each couple of minutes. Keep in mind
# it doesn't make much sense to launch it more frequently than your record TTL
# and author assumes no responsibility if you misuse it and get throttled at Aamazon Route53
# there shall be a file with AWS secrets in JSON format, inspired by dnscurl to hide your secrets
# from command line
#
# create a file with your AWS credentials:
#{
#  "access_key" : "SOME_NON_SECRET",
#  "secret_key" : "SOME_SECRET"
#}
#
# create a file with hosted zone(s) in JSON format:
#{
#  "name":"ZONE_ID",
#  "name":"ZONE_ID"
#}
# the name label is purely cosmetic and for logging purposes.
#
# launch parameters:
# ./route53_ddns.rb --secrets-file /path/r53_secrets.json --hosted-zones /path/r53_zones.json --random-sleep

require 'rubygems'
require 'curb'
require 'json'
require 'optparse'
require 'ostruct'
require 'route53'

# Route53 endpoint
$ENDPOINT = 'https://route53.amazonaws.com/'
$API_VERSION = '2012-02-29'

def get_cli_options args
  options = OpenStruct.new
  options.secrets_file = ""
  options.hosted_zones = ""
  options.sleep = false

  opts = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [options]"

    opts.on("-s", "--secrets-file [FILENAME]", "AWS access and secret key locations") do |val|
      options.secrets_file = val
    end

    opts.on("-z", "--hosted-zone [FILENAME]", "Route53 hosted zone ids") do |val|
      options.hosted_zones = val
    end

    opts.on("-b", "--[no-]random-sleep", "Random sleep of up to 1 minute enabled") do |val|
      options.sleep = val
    end

    opts.on_tail("-h", "--help", "Show this message") do
      puts opts
      exit 0
    end
  end

  begin
    opts.parse!(args)
  rescue
    puts "Cannot parse input parameters"
    puts opts
    exit 1
  end
  [ options.secrets_file, options.hosted_zones ].each do |x|
    if x.empty?
      puts opts
      exit 1
    end
  end

  options
end

# if you want to run internal DNS just replace this function with something like
# required to figure out local IP address, one can use info returned form /sbin/ficonfig as well
# example code taken from http://coderrr.wordpress.com/2008/05/28/get-your-local-ip-address/
# require 'socket'
# def get_my_ip
#   orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily
#
#   UDPSocket.open do |s|
#     s.connect 'example.com', 1
#     s.addr.last
#   end
# ensure
#   Socket.do_not_reverse_lookup = orig
# end

# define a bunch of services, that provide you with IP
# among with a function, that will help to extract it
# Amazon AWS one shall be enough though
def get_my_ip
  ip_providers = [
    {
      'url' => 'http://whatismyip.org/',
      'method'  =>  lambda { |x| x },
      'validate' => lambda { |x| x =~ /^([\d]{1,3}\.){3}[\d]{1,3}$/ }
    },
    {
      'url' => 'http://strewth.org/ip.php',
      'method' => lambda { |x| JSON.parse(x)['ipaddress']; },
      'validate' => lambda { |x| JSON.parse(x).has_key?('ipaddress') }
    },
    {
      'url' => 'http://checkip.amazonaws.com/',
      'method' => lambda { |x| x },
      'validate' => lambda { |x| x =~  /^([\d]{1,3}\.){3}[\d]{1,3}$/ }
    }
  ].shuffle

  # choose a random ip provider, then iterate ahead from it
  ip_good = false
  my_ip = nil
  ip_providers.each do |provider|
    puts "Polling #{provider['url']}"
    # do a request
    begin
      curl = Curl::Easy.new(provider['url'])
      data = curl.http(:get)
      response = curl.body_str

      if provider['validate'].call(response)
        my_ip = provider['method'].call(response)
        if my_ip =~ /^([\d]{1,3}\.){3}[\d]{1,3}$/
          ip_good = true
          break
        else
          warn "Result is not a dotted quad IP"
        end
      else
        warn "Bad response from IP lookup server. Retrying"
      end
    rescue => e
      # assuming first two lines won't throw
      warn "Error encountered during http request. " + e.inspect
    end
  end

  if not ip_good
      puts "Cannot get current IP from any of external services."
      exit 1
  end
  my_ip.strip
end

# assuming that target HostedZone contains only one A record
# otherwise this script is not what you are looking for

#TODO: write a generalized method to deal with {A,MX,CNAME} record type

def get_A_record (r53, hzid)
  zones = r53.get_zones
  # /hostedzone/[HZID]
  the_zone = zones.select { |zone| zone.host_url.split('/')[2] == hzid }

  if the_zone.nil? or the_zone.size != 1
    puts "Cannot find hosted zone"
    return nil
  end

  records = the_zone[0].get_records('A')
  if (records.size() != 1)
    puts "It is assumed that only one A record exists in Hosted Zone to update"
    exit 1
  end

  records[0]
end

#TODO support mail records in the format of '10 subdomain.domain.tld', e.g., mail.example.com
def get_MX_record (r53, hzid)
  zones = r53.get_zones
  # /hostedzone/[HZID]
  the_zone = zones.select { |zone| zone.host_url.split('/')[2] == hzid }

  if the_zone.nil? or the_zone.size != 1
    puts "Cannot find hosted zone"
    return nil
  end

  records = the_zone[0].get_records('MX')
  if (records.size() != 1)
    puts "It is assumed that only one MX record exists in Hosted Zone to update"
    exit 1
  end

  records[0]
end

def get_CNAME_record (r53, hzid)
  zones = r53.get_zones
  # /hostedzone/[HZID]
  the_zone = zones.select { |zone| zone.host_url.split('/')[2] == hzid }

  if the_zone.nil? or the_zone.size != 1
    puts "Cannot find hosted zone"
    return nil
  end

  records = the_zone[0].get_records('CNAME')
  # return an array to iterate through update() calls
  return records
end


# Route53 is authoritative source of domain name
# anythig else is just a cache, that might become stale
# or prone to invalidation issues. One request per 5 minutes shall
# not be a problem
def get_previous_ip(r53, hzid)
    get_A_record(r53, hzid).values[0]
end

def update_ip (r53, hzid, ip)

  #get_<type>_record calls will return nil if the hosted zone ID is not found.
  puts "Updating zone A record."
  a_rec = get_A_record(r53, hzid)
  a_rec.update(nil, nil, nil, [ip]) unless a_rec.nil?
  
  puts "Updating zone MX record."
  mx_rec = get_MX_record(r53, hzid)
  mx_rec.update(nil, nil, nil, ["10 #{ip}"]) unless mx_rec.nil?

  puts "Updating zone CNAME (e.g., subdomain alias or wildcard '*.domain.tld') record"
  cname_rec = get_CNAME_record(r53, hzid)
  # iterate through the array of CNAME records
  cname_rec.each do |rec|
    rec.update(nil, nil, nil, [ip]) unless cname_rec.nil?
  end
end

options = get_cli_options(ARGV)

# sleep for <60 secs to try to distribute load on Route 53 in case
# if script is too popular see also http://www.stdlib.net/~colmmacc/2009/09/14/period-pain/
if options.sleep
  require 'zlib'
  require 'socket'
  # take hash of hostname, which is supposed to be more or less different
  hash = Zlib.crc32(Socket.gethostname,0).to_i
  # shall we relax a bit and don't care much about bias?
  sleep_secs = hash % 60
  puts "Sleeping for #{sleep_secs} seconds before update"
  sleep(sleep_secs)
end

my_ip = get_my_ip
puts "IP is #{my_ip}"

# get secrets file
secrets = JSON.parse(File.read(options.secrets_file))

#TODO use the route53 Connection::get_zones() method?
#get zones file
zones = JSON.parse(File.read(options.hosted_zones))

puts "Updating these hosted zones:"
puts zones

r53 = Route53::Connection.new(secrets["access_key"], secrets["secret_key"], $API_VERSION, $ENDPOINT)

zones.each_pair do |key, value|

  previous_ip = get_previous_ip(r53, value)
  puts "#{key} IP was #{previous_ip}"

  if previous_ip == my_ip
    puts "Nothing to do."
  else
    puts "Updating IP of #{key} with Route53"
    update_ip(r53, value, my_ip)
    puts "Done."
  end
end
