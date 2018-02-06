'''
Created on 12 Dec 2017

@author: lia
'''
import threading
import errno, sys
import struct
from socket import socket, timeout, error

from gtp_v2_core.commons.gtp_v2_commons import GTPmessageTypeStr

from gtp_v2_attacks.InformationGathering.commons import GTP_C_PORT, message_queue, GTPResponse2Request

class Listener(threading.Thread):
    '''
    classdocs
    '''


    def __init__(self, open_sock, isVerbose=True):
        threading.Thread.__init__(self)
        
        self.TAG_NAME = 'PATH MANAGEMENT_LISTENER'
        
        self.sock = open_sock
        self.is_verbose = isVerbose
        self.is_running = False
        
    ##
    ## @brief      Determines if the thread is running
    ##
    ## @param      self  refers to the class itself
    ##
    ## @return     True if running, False otherwise.
    ##    
    def isRunning(self):
        return self.is_running
                
    ##
    ## @brief      Starts the execution of the thread
    ##
    ## @param      self  refers to the class itself
    ##
    def run(self):          
        if self.is_verbose: 
            print "\n\n--: PATH MANAGEMENT MANAGER :--"            
            print "Keep working on the opened connection"
            
        self.is_running = True
        while self.sock is not None and self.is_running:
            try:
                data, addr = self.sock.recvfrom(1024)            
                if len(data) > 8 :                      
                    (flags, msg_type, length, sequence) = struct.unpack("!BBHL", 
                                                                data[:8])
                    version = flags & 0x40 
                    if version != 2 :
                        print "%s:Unsupported GTP version %02x"%(self.TAG_NAME, 
                                                                 version)
                        continue
                    if not message_queue.has_key(addr[0]) :
                        continue
                    if GTPResponse2Request[msg_type] != message_queue[addr[0]]['msg_type'] :
                        continue
                    message_queue[addr[0]]['reply'] = 1
                    
                    if self.is_verbose:                        
                        print "%s: %s sent response %s"%(self.TAG_NAME,
                                                    addr[0],
                                                    GTPmessageTypeStr[msg_type])            
            except timeout, e:
                print "%s: TIMEOUT_ERROR: %s" % (self.TAG_NAME, e)
                break
            except error, e:
                if e.errno == errno.EBADFD:
                    print "%s: BAD_FILE_DESCRIPTOR_ERROR: %s"%(self.TAG_NAME, e)
                    break
                elif e.errno == errno.EPIPE:
                    print "%s: BROKEN_PIPE_ERROR: %s"%(self.TAG_NAME, e)
                    break
                else:
                    print "%s: UNKNOWN_ERROR: %s"%(self.TAG_NAME, e)
                    break
            except Exception, e:
                print "%s:GENERIC ERROR : %s"%(self.TAG_NAME, e)
                break 
    
    ##
    ## @brief      Stops the execution of the thread
    ##
    ## @param      self  refers to the class itself
    ##
    def stop(self):
        if not self.is_running:
            return
        
        self.is_running = False
        
        if self.is_verbose: 
            print"Stopped %s"%(self.TAG_NAME)
                