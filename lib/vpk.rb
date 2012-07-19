require "vpk/version"
require 'logger'
require 'zlib'
require 'find'
require 'stringio'
require 'fileutils'

module VPK
  class VPKHeader
    attr_accessor :signature
    attr_accessor :version
    attr_accessor :directory_length

    VPK_SIGNATURE = 0x55aa1234
    VERSION = 1
  end

  class VPKDirectoryEntry
    attr_accessor :extension
    attr_accessor :path
    attr_accessor :file

    attr_accessor :crc
    attr_accessor :preload_bytes
    attr_accessor :archive_index
    attr_accessor :entry_offset
    attr_accessor :entry_length
    attr_accessor :terminator

      attr_accessor :payload

    def self.load_from(path)
      entry = VPKDirectoryEntry.new
      entry.payload = File.read(path)
      entry.full_path = path
      entry
    end

    def full_path
      if path == " "
        "#{file}.#{extension}"
      else
        "#{path}/#{file}.#{extension}"
      end
    end

    def full_path=(path)
      (path, file) = File.split(path)
      ext = File.extname(file)
      if path == "."
        path = ""
      end

      @path = path.gsub(/^\.\.?\//, "")
      @extension = ext.gsub(/^./, "")
      @file = File.basename(file, ext)
    end

    def read_payload(io, end_of_header = 0)
      io.seek(end_of_header + @entry_offset)
      @payload = io.read(@entry_length + @preload_bytes)
    end

    def valid?
      puts @payload
      @crc == Zlib.crc32(@payload)
    end

    def mkdir_p
      FileUtils.mkdir_p(@path)
    end

    def write_to_file(bath_path = nil)
      File.open(full_path, "wb") do |file|
        file.write @payload
      end
    end
  end

  class VPKFile
    attr_accessor :header
    attr_accessor :dir_entries

    @@logger = Logger.new(nil)
    def self.logger=(new_logger)
      @@logger = new_logger
    end

    def initialize(path=nil)
      return if path.nil?

      @@logger.info "extract vpk file #{path.inspect}"
      File.open(path, "rb") do |io|
        @header = VPKHeader.new
        @header.signature = io.read(4).unpack("V*").first
        @header.version = io.read(4).unpack("V*").first
        @header.directory_length = io.read(4).unpack("V*").first
        @@logger.info "reading header: #{@header.inspect}"
        end_of_header = io.pos

        unless @header.signature == "0x55aa1234".hex
          @@logger.error "signature is invalid: #{@header.signature.inspect}"
          raise VPKFileFormatError
        end

        @@logger.info "signature is valid"

        @dir_entries = read_directory(io)

        @dir_entries.each do |entry|
          @@logger.info "try to read #{entry.full_path} (#{entry.entry_length} bytes)"
          entry.read_payload(io, end_of_header + @header.directory_length)
          unless entry.valid?
            @@logger.error "crc is invalid: #{entry.crc.inspect}"
            raise VPKFileInvalidCRCError
          end
          @@logger.info "done"
        end
      end
    end

    def self.open(path, &block)
      file = self.new(path)
      block.call file
    end

    def self.entries(path, &block)

      file = self.new(path)
      file.dir_entries
    end

    def to_file_struct_tree
      map = {}
      @dir_entries.each{ |entry|
        map[entry.extension] ||= {}
        map[entry.extension][entry.path] ||= []
        map[entry.extension][entry.path] << entry
      }
      map
    end

    def to_blob
      @header.directory_length = calc_directory_length
      @@logger.debug "calculated directory length: #{@header.directory_length}"

      StringIO.open("") do |io|
        io.write([@header.signature].pack("I*"))
        io.write([@header.version].pack("I*"))
        io.write([@header.directory_length].pack("I*"))

        write_directory(io)

        io.rewind
        return io.read
      end
    end

    def extract_to(base_dir)
      @dir_entries.each{ |entry|
        unless entry.path == " "
          path = File.join(base_dir, entry.path)
          FileUtils.mkdir_p path
        end
        file_path = File.join(base_dir, entry.full_path)
        File.write file_path, entry.payload
      }
    end

    def self.archive(target_dir)
      vpk = VPKFile.new
      vpk.header = VPKHeader.new
      vpk.header.signature = VPKHeader::VPK_SIGNATURE
      vpk.header.version = VPKHeader::VERSION
      vpk.header.directory_length = nil
      vpk.dir_entries = []

      Find.find(target_dir){ |f|
        next if File.directory?(f)
        entry = VPKDirectoryEntry.new
        entry.full_path = f.gsub(/^#{target_dir}(\/)?/, "")
        entry.payload = File.read(f)
        vpk.dir_entries << entry
      }
      vpk
    end

    def write_to(path)
      File.write path, to_blob
    end

    def to_s
      "#<VPKFile: #{self.object_id} @header=#{@header.inspect} @files=#{self.dir_entries.size}>"
    end

    private
    def calc_directory_length
      len = 0
      to_file_struct_tree.each{ |extension, path_map|
        len += extension.size + 1
        path_map.each{ |path, entries|
          len += path.size + 1
          entries.each{ |entry|
            len += entry.file.size + 1
            len += 18 #preload data分
          }
          len += 1
        }
        len += 1
      }
      len += 1
    end

    def read_string(io)
      string = ""
      while true
        b = io.readbyte
        if b == 0
          return string
        end
        string += b.chr
      end
    end

    # write null terminate string
    def write_string(io, string)
      io.write string
      io.write "\x00"
    end

    def read_directory(io)
      dir_entries = []
      while true
        extension = read_string(io)
        @@logger.debug "extension = #{extension.inspect}"
        break if extension == ""

        while true
          path = read_string(io)
          @@logger.debug "path = #{path.inspect}"
          break if path == ""

          while true
            file = read_string(io)
            @@logger.debug "file = #{file.inspect}"
            break if file == ""

            dir_entry = read_file_info_and_preload_data(io)
            dir_entry.extension = extension
            dir_entry.path = path
            dir_entry.file = file
            dir_entries << dir_entry
          end
        end
      end
      dir_entries
    end

    def write_directory(io)
      end_of_header = io.pos

      total_offset = 0
      to_file_struct_tree.each{ |extension, path_map|
        write_string(io, extension)

        path_map.each{ |path, entries|
          @@logger.debug "write path: #{path.inspect}"
          write_string(io, path)
          entries.each{ |entry|
            write_string(io, entry.file)

            entry.archive_index = 0x7fff
            entry.terminator = 0xffff
            entry.preload_bytes = 0
            entry.entry_length = entry.payload.size
            entry.entry_offset = total_offset
            total_offset += entry.entry_length
            write_file_info_and_preload(io, entry)

            pos = io.pos
            io.seek(end_of_header + @header.directory_length + entry.entry_offset)
            io.write(entry.payload)
            io.seek(pos)
          }
          io.write "\x00"
        }
        io.write "\x00"
      }
      io.write "\x00"
    end

    def read_file_info_and_preload_data(io)
      entry = VPKDirectoryEntry.new
      entry.crc = io.read(4).unpack("V*").first
      entry.preload_bytes = io.read(2).unpack("v*").first
      entry.archive_index = io.read(2).unpack("v*").first
      entry.entry_offset = io.read(4).unpack("v*").first
      entry.entry_length = io.read(4).unpack("v*").first
      entry.terminator = io.read(2).unpack("v*").first
      @@logger.debug "read entry_offset: #{entry.entry_offset}, entry_length: #{entry.entry_length}"
      entry
    end

    def write_file_info_and_preload(io, entry)
      entry.crc = Zlib.crc32(entry.payload)
      io.write [entry.crc].pack("i*")
      io.write [entry.preload_bytes].pack("S*")
      io.write [entry.archive_index].pack("S*")
      io.write [entry.entry_offset].pack("I*")
      io.write [entry.entry_length].pack("I*")
      io.write [entry.terminator].pack("S*")
      @@logger.debug "write entry_offset: #{entry.entry_offset}, entry_length: #{entry.entry_length}"
      entry
    end
  end

  module VPKUtil
    def self.extract(in_vpk_path, output_path)
      VPKFile.new(in_vpk_path).extract_to(output_path)
    end

    def self.archive(dir_path, out_vpk_path)
      VPKFile.archive(dir_path).write_to(out_vpk_path)
    end
  end

  class VPKError < StandardError; end
  class VPKFileFormatError < VPKError; end
  class VPKFileInvalidCRCError < VPKError; end
end
