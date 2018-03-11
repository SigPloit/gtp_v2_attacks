#!/usr/bin/env python
# encoding: utf-8
'''
main -- shortdesc

main is a description

It defines classes_and_methods

@author:     Rosalia d'Alessandro

@copyright:  2017. All rights reserved.

@license:    license

@contact:    list_mailing@libero.it
'''

import os
import sys
from optparse import OptionParser
from gtp_v2_core.utilities.configuration_parser import parseConfigs

from commons.message_handler import MessageHandler

from commons.globals import message_queue


__all__ = []
__version__ = 0.1


GTP_PORT = 2123
DEFAULT_MSG_FREQ = 20
DEFAULT_SLEEPTIME = 1
DEBUG = 0

def main(argv=None):
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])
    program_version = "v0.1"

    program_version_string = '%%prog %s' % (program_version)

    program_license = "Copyright 2017 Rosalia d'Alessandro\
                Licensed under the Apache License 2.0\
                http://www.apache.org/licenses/LICENSE-2.0"

    if argv is None:
        argv = sys.argv[1:]
    lstn = None
    try:
        # setup option parser
        parser = OptionParser(version = program_version_string, 
                description = program_license)
        
        parser.add_option("-v", "--verbose", dest = "verbose", action = "count", 
                help = "Set verbosity level [default: %default]")

        parser.add_option("-c", "--config", dest = "config_file", 
                help = "Configuration file")
        
        parser.add_option("-r", "--remote_net", dest = "remote_net", 
                help = "Remote network e.g. 10.0.0.0/24, 10.0.0.1/32") 
        
        parser.add_option("-l", "--listening", dest = "listening_mode", 
                action = "count", help = "Start also a GTP_C listener")       
        
        parser.add_option("-o", "--output", dest = "output_file", 
                help = "Output file") 
        
        # set defaults
        parser.set_defaults(listening_mode = False, verbose = False,
                    config_file = "../config/TeidDiscover.cnf",
                    output_file = "")

        # process options
        (opts, args) = parser.parse_args(argv)
        is_verbose = False
        listening_mode = opts.listening_mode
          

        msg_freq = DEFAULT_SLEEPTIME
        remote_net = opts.remote_net
        sleep_time = DEFAULT_SLEEPTIME
      
        if listening_mode and  remote_net == None:
            print "remote network (e.g. 10.0.0.0/24, 10.0.0.1/32) is required"
            return
        
        # MAIN BODY #
        if opts.config_file == "" :
            print "Error: missed config file"
            return            
  
        config = parseConfigs(opts.config_file)
 
        msgs = config.get_unpacked_messages()
       
        lstn = MessageHandler(messages = msgs, peer = remote_net, 
                              isVerbose = is_verbose, listening_mode = listening_mode,
                              msgs_freq = msg_freq, wait_time = sleep_time)  
        if lstn : 
            lstn.daemon = True
            lstn.start()
            lstn.join()
            lstn.stop()
        print "Sent %d GTPV2 messages"%len(message_queue)
        fd = None
        if not listening_mode :
            return
        if opts.output_file != "" :
            fd = open('opts.output_file ', 'w')
        for key, value in message_queue.items():
            for k, v in value:
                if v['reply'] == 1:
                    print "%s implements a GTP v2 stack"%key
                    print "%d msg type teid %d"%(k, v['remote_teid'])    
                    if fd :
                        fd.write("%s implements a GTP v2 stack"%key)   
                        fd.write("%d msg type teid %d"%(k, v['remote_teid']))
    except Exception, e:
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        print "Exception %s"%str(e)
        if lstn : 
            lstn.stop()        
        return 2
if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-v")
    sys.exit(main())
