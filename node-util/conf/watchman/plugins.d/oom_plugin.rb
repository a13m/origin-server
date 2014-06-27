#--
## Copyright 2014 Red Hat, Inc.
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##    http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##++
#
require 'openshift-origin-node/model/watchman/watchman_plugin'
require 'ffi'
require 'ffi/tools/const_generator'
require "eventmachine"

$cgroot = "/cgroup/memory/openshift"

module EventFD
  extend FFI::Library
  ffi_lib 'c'
  ['EFD_CLOEXEC','EFD_NONBLOCK','EFD_SEMAPHORE'].each do |const|
    const_set(const,FFI::ConstGenerator.new(nil, :required => true) do |gen|
      gen.include 'sys/eventfd.h'
      gen.const(const)
    end[const].to_i)
  end
  attach_function :eventfd, [:uint, :int], :int
end

class OomPlugin < OpenShift::Runtime::WatchmanPlugin
  def initialize(config, logger, gears, operation)
    super

    return if disabled?

    @gears_last_updated = nil

    @event_watcher = ::OpenShift::Runtime::WatchmanPlugin::EventWatcher.new(@config)
    # @event_watcher.gears_updated(@gears)
    @event_watcher.start
  end

  def apply(iteration)
    return if disabled?

    if @gears_last_updated.nil? or @gears.last_updated != @gears_last_updated
      @event_watcher.gears_updated(@gears)
      @gears_last_updated = @gears.last_updated
    end
  end

  def disabled?
    # @disabled ||= @config.get('WATCHMAN_OOM_EVENTFD_ENABLED') != 'true'
    return false
  end
end

module OpenShift
  module Runtime
    class WatchmanPlugin
      class EventWatcher
        DEFAULT_INTERVAL = 60

        attr_reader :delay, :config

        def initialize(config)
          @config = config
          Syslog.info "Initializing Watchman OOM Eventfd plugin"

          # Set the sleep time for the metrics thread
          # default to running every 60 seconds if not set in node.conf
          @delay = Integer(@config.get('WATCHMAN_OOM_EVENTFD_INTERVAL')) rescue DEFAULT_INTERVAL

          Syslog.info "Watchman OOM eventfd interval = #{@delay}s"

          @mutex = Mutex.new
        end

        def gear_metadata
          @gear_metadata ||= Hash.new do |all_md, uuid|
            all_md[uuid] = OOM_Listener.new(uuid)
          end
        end


        # Cache the metadata for each gear
        def gears_updated(gears)
          # need to sync modifications to gear_metadata
          @mutex.synchronize do
            seen = []

            gears.ids.each do |uuid|
              # keep track of each uuid we've seen this time
              seen << uuid

              # add the uuid to the metadata if it's new;
              # data will be loaded lazily via Hash.new block above
              gear_metadata[uuid].watch unless gear_metadata.has_key?(uuid)
            end

            # remove metadata for all uuids that previously were in gear_metadata
            # but are no longer in the active gears list
            gear_metadata.delete_if { |key, value| !seen.include?(key) && gear_metadata[key].unwatch }
          end
        end

                # Step that is run on each interval
        #
        # Mutex acquired and held for duration of method
        def tick
          # need to sync access to gear_metadata
          @mutex.synchronize do
            if gear_metadata.size > 0
              Syslog.info("Watching #{gear_metadata.size} gears")
            end
          end
        rescue => e
          Syslog.info("OOM: unhandled exception #{e.message}\n" + e.backtrace.join("\n"))
        end

        def start
          Thread.new do
            Syslog.info("revving up the machine")
            begin
              EM.run {
                tick
                EM.add_periodic_timer(@delay) do
                  Syslog.info("event loop")
                  tick
                end
              }
            rescue => e
              Syslog.info("EM thread crash: #{e.message}")
            end
          end
        end
      end

      class OOM_Listener
        attr_accessor :efd
        attr_accessor :ofd
        attr_accessor :ev
        attr_accessor :conn
        attr_reader   :uid

        def initialize(uid)
          @ev = nil
          @ofd = nil
          @efd = nil
          @conn = nil
          @uid = uid

          Syslog.info("Add listener object for #{@uid}")

        end

        def open
          @ev = EventFD.eventfd(0, EventFD::EFD_NONBLOCK)
          @ofd = File.open("#{$cgroot}/#{@uid}/memory.oom_control")
          IO.write("#{$cgroot}/#{@uid}/cgroup.event_control","#{@ev} #{@ofd.fileno}")
          @efd = IO.for_fd(@ev,"r+b")
        end

        def close
          return nil if @conn == nil
          @conn.detach
          @efd.close
          @ofd.close
          @conn = nil
        end

        # TODO: throw away events already pending when we start watching?
        def watch
          return if self.conn != nil
          Syslog.info("watching #{@uid}")
          self.open
          EM.watch @efd do |conn|
            class << conn
              attr_accessor :efd
              attr_accessor :uid
              def notify_readable
                data = @efd.read_nonblock(8).unpack('Q')[0]
                Syslog.info("#{@uid} received OOM event (#{data})")
                fixer = Fixer.new(@uid)
                fixer.fix
              end
            end
            conn.efd = @efd
            conn.uid = @uid
            conn.notify_readable = true
            @conn = conn
          end
        end

        def unwatch
          return if self.conn == nil
          Syslog.info("unwatching #{@uid}")
          self.close
        end
      end

      class Fixer
        MEMSW_LIMIT = 'memory.memsw.limit_in_bytes'
        OOM_OP_TIMEOUT = 30
        PLUGIN_NAME = "OOM Fixer"

        def initialize(uuid)
          @uuid = uuid
          @memsw_multiplier = 1.1
        end

        def try_cgstore(cg, attr, value, retries=3)
          1.upto(retries) do
            begin
              cg.store(attr, value)
              return true
            rescue
              sleep 1
            end
          end
          return false
        end

        def try_cgfetch(cg, attr, retries=3)
          1.upto(retries) do
            begin
              return cg.fetch(attr).to_i
            rescue
              sleep 1
            end
          end
          return nil
        end

        def fix
          #store memory limit
          # Should we infer the template from the current values?
          cg = OpenShift::Runtime::Utils::Cgroups.new(@uuid)
          restore_memsw_limit = cg.templates[:default][MEMSW_LIMIT].to_i
          orig_memsw_limit = try_cgfetch(cg, MEMSW_LIMIT)

          # Increase limit by 10% in order to clean up processes. Trying to
          # restart a gear already at its memory limit is treacherous.
          increased = (orig_memsw_limit * @memsw_multiplier).round(0)
          Syslog.info %Q(#{PLUGIN_NAME}: Increasing memory for gear #{@uuid} to #{increased} and restarting)
          ret = try_cgstore(cg, MEMSW_LIMIT, increased)
          Syslog.info %Q(#{PLUGIN_NAME}: Failed to increase memory limit for gear #{@uuid}) unless ret

          begin
            # If gear is under OOM and OOM kill is enabled, skip this and go
            # straight to kill_procs / restart, since the gear has already
            # received kill signals, and if it's wedged, spawning more
            # processes for stop action will just make the kernel do more work.
            if true # oom_control['oom_kill_disable'] == '1'
              begin
                out, err, rc = ::OpenShift::Runtime::Utils.oo_spawn("oo-admin-ctl-gears forcestopgear #{@uuid}", timeout: OOM_OP_TIMEOUT)
                # Does rc == 0 here indicate success when forcestop is used?
                # Also, does forcestop actually get to its "pkill -9" if
                # the gear is under OOM?
                # NB: memory reset and gear restart happen in the "ensure" block
                return unless rc != 0
                Syslog.info %Q(#{PLUGIN_NAME}: Force stop failed for gear #{@uuid} , rc=#{rc}")
              rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
                Syslog.info %Q(#{PLUGIN_NAME}: Force stop failed for gear #{@uuid}: #{e.message}")
                # This is primarily to catch timeouts
              end
            end

            sleep 5

            # Verify that we are ready to reset to the old limit
            current = try_cgfetch(MEMSW_USAGE) || increased
            app = ::OpenShift::Runtime::ApplicationContainer.from_uuid(@uuid)

            while current > restore_memsw_limit && retries > 0
              increased = (increased * @memsw_multiplier).round(0)
              Syslog.info %Q(#{PLUGIN_NAME}: Increasing memory for gear #{@uuid} to #{increased} and killing processes)
              ret = try_cgstore(MEMSW_LIMIT, increased)
              Syslog.info %Q(#{PLUGIN_NAME}: Failed to increase memory limit for gear #{@uuid}) unless ret

              app.kill_procs()
              sleep 5
              retries -= 1
              current = try_cgfetch(MEMSW_USAGE) || current
            end

          ensure
            # Reset memory limit
            ret = try_cgstore(MEMSW_LIMIT, restore_memsw_limit)
            Syslog.warning %Q(#{PLUGIN_NAME}: Failed to lower memsw limit for gear #{@uuid} from #{increased} to #{orig_memsw_limit}) unless ret

            # Finally, restart
            begin
              out, err, rc = ::OpenShift::Runtime::Utils.oo_spawn("oo-admin-ctl-gears startgear #{@uuid}")
            rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
              Syslog.info %Q(#{PLUGIN_NAME}: Start failed for gear #{@uuid}: #{e.message}")
            end
          end
        end
      end

    end
  end
end

