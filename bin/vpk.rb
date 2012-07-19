#!/bin/env ruby
# encoding: utf-8
# Author: kimoto
require 'vpk'
require 'optparse'

options = {}

opt = OptionParser.new
opt.banner = "#{File.basename($0)} [options] <dirname or vpkfile>"
opt.on("-c", "create archive"){ |v| options[:mode] = :archive }
opt.on("-x", "extract mode"){ |v| options[:mode] = :extract }
opt.parse! ARGV

VPK::VPKFile.logger = Logger.new(STDERR)

case options[:mode]
when :archive
  path = ARGV.shift
  if File.directory? path
    after_path = path + ".vpk"
    if File.exists? after_path
      STDERR.puts "already exist file: #{after_path}"
      exit(1)
    else
      puts "compressed #{path} -> #{after_path}"
      VPK::VPKFile.archive(path).write_to(after_path)
    end
  else
    STDERR.puts "not directory: #{path}"
    exit(1)
  end
when :extract
  path = ARGV.shift
  if File.exists? path
    VPK::VPKFile.new(path).extract_to("./")
    puts "extracted!: #{path}"
  else
    STDERR.puts "not found specified file: #{path}"
    exit(1)
  end
else
  STDERR.puts "illegal argument error!: #{options[:mode].inspect}"
  puts opt.help
  exit(1)
end

