'''
Created on 12 Dec 2017

@author: lia
'''
import threading
import errno, sys
import struct
from socket import socket, timeout, error

from gtp_v2_core.commons.gtp_v2_commons import GTPmessageTypeStr

from gtp_v2_attacks.InformationGathering.commons import message_queue,\
    GTPResponse2Request
from gtp_v2_core.utilities.utilities import logNormal, logErr, logOk , logWarn

class Listener(threading.Thread):
    '''
    classdocs
    '''


    def __init__(self, open_sock, isVerbose=True):
        threading.Thread.__init__(self)
        
        self.TAG_NAME = 'GTP LISTENER'
        
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
      
    def __getFTEID(self, data):          
        if data is None or len(data) == 0:
            raise Exception("%s: invalid data"%self.TAG_NAME)
        i = 0
        teid = 0x00
        while i < len(data) :
            (ie_type, ie_len, spare_instance) = struct.unpack("!BHB", 
                                                                data[i: i+4])
            if ie_type != 87:
                i += (4 + ie_len)
            teid = struct.unpack("!L", data[i+4: i+8])
            break
        return teid
    ##
    ## @brief      Starts the execution of the thread
    ##
    ## @param      self  refers to the class itself
    ##
    def run(self):                    
        self.is_running = True
        while self.sock is not None and self.is_running:
            try:
                data, addr = self.sock.recvfrom(1024)            
                if len(data) > 8 :                      
                    (flags, resp_msg_type, length, sequence_or_teid) = struct.unpack("!BBHL", 
                                                                data[:8])
                    version = flags & 0x40 
                    if version != 2 :
                        logWarn("Unsupported GTP version %02x"%(version), 
                                verbose = self.is_verbose, TAG = self.TAG_NAME)
                        continue
                    if not message_queue.has_key(addr[0]):
                        logWarn("Unmanaged IP %s"%(addr[0]),
                                verbose = self.is_verbose, TAG = self.TAG_NAME)                        
                        continue
                    req_msg_type = GTPResponse2Request[resp_msg_type]
                    if not message_queue[addr[0]].has_key(req_msg_type):
                        logWarn("Unsolicites response msg %d"%(resp_msg_type),
                                verbose = self.is_verbose, TAG = self.TAG_NAME) 
                        continue

                    message_queue[addr[0]][req_msg_type]['reply'] = 1
                    logWarn("Received response to sent msg %d from ip %s"%(
                        GTPmessageTypeStr[req_msg_type], addr[0]), 
                            verbose = self.is_verbose, TAG = self.TAG_NAME) 
                    if req_msg_type != 32 :
                        continue
                    if message_queue[addr[0]][req_msg_type]['local_teid'] != \
                        sequence_or_teid :
                        continue  
                    message_queue[addr[0]][req_msg_type]['remote_teid'] = \
                    self.__getIE(data[12:])
            except timeout, e:
                if addr[0] :
                    logErr("%s TIMEOUT_ERROR"%(addr[0]), TAG = self.TAG_NAME)
                else:
                    logErr("TIMEOUT_ERROR", TAG = self.TAG_NAME)                         
                pass
            except error, e:
                if e.errno == errno.EBADFD:
                    if addr[0] :                    
                        logErr("%s BAD_FILE_DESCRIPTOR_ERROR"%(addr[0]), 
                                TAG = self.TAG_NAME) 
                    else:
                        logErr("BAD_FILE_DESCRIPTOR_ERROR", TAG = self.TAG_NAME)                    
                    break
                elif e.errno == errno.EPIPE:
                    if addr[0] : 
                        logErr("%s BROKEN_PIPE_ERROR"%(addr[0]), 
                            TAG = self.TAG_NAME)  
                    else:
                        logErr("BROKEN_PIPE_ERROR", TAG = self.TAG_NAME)   
                    break
                else:
                    logErr("UNKNOWN ERROR: %s"%(e), TAG = self.TAG_NAME) 
                    break
            except Exception, e:
                logErr("GENERIC ERROR: %s"%(e), TAG = self.TAG_NAME)
                break 
    
    ##
    ## @brief      Stops the execution of the thread
    ##
    ## @param      self  refers to the class itself
    ##
    def stop(self):
        if not self.is_running:
            logWarn("is not running", verbose = self.is_verbose, 
                    TAG = self.TAG_NAME)            
            return        
        self.is_running = False
        logOk("Stopped", verbose = self.is_verbose, TAG = self.TAG_NAME) 
                