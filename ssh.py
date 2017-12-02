"""
Author:lgunupud@cisco.com
Date Created: 15th April-2015
Description: This class is used to execute command on linux machine and cae confd using ssh
"""
import pexpect
import re
import os
import time
import logging
logging.basicConfig()

prompt_regex = { 
     #'linux' : '\[.*\][\]\$\>\#]\s$', 
     #'linux': ".*\@.*\:.*\#",
     'linux':"#",
}
line_delimiter = {
    'linux' : '\n',
}

LOGGING_LEVELS = {'critical': logging.CRITICAL,
                  'error': logging.ERROR,
                  'warning': logging.WARNING,
                  'info': logging.INFO,
                  'debug': logging.DEBUG}

class SSH:

    """
    Author:Lakshman;
    Desc:This method will intialize the ssh object"
    """
    def __init__(self, host, username, password, type = 'linux'):
        try:
            self.host = host
            self.username = username
            self.adminpassword = password
            self.type = type
            self.connection = None
            self.error_string = ""
            self.log = logging.getLogger()
        except Exception,e:
                self.log.error("Exception Occured: Not able to intialize ssh object")
                self.log.error(str(e))
                return False

    """
    Desc:This method will open ssh connection"
    index,index1,2,3,4 are the index values of corresponding expect list
    """
    def open_ssh_session(self):
        try:
            prompt = prompt_regex["linux"]
            command_ssh = "ssh %s@%s" %(self.username,self.host)
            self.log.info("Executing: " + command_ssh)
            try:
                self.connection = pexpect.spawn(command_ssh)
            except Exception,e:
                self.log.error("Not able to execute command " + command_ssh) 
                self.log.error(self.host + " is down or pexpect error")
                self.log.error(str(e))
                return False
            
            expect_key = ['authenticity', '[pP]assword:', pexpect.TIMEOUT]
            index = self.connection.expect(expect_key)
            if index == 0:
                self.connection.sendline('yes')
                self.connection.expect(expect_key)
            elif index == 1:
                self.log.info("sending admin password.....")
                self.connection.sendline(self.adminpassword)
                #index1 = self.connection.expect([prompt,pexpect.TIMEOUT])
                index1 = self.connection.expect(['#'])
                if index1 == 0:
                    self.log.info("SSH Session opened successfully")
                    return True                    
                else:    
                    self.log.error("Error: Did not get the prompt after providing the password")
                    return False
                
            elif index == 2:
                self.log.error("Timeout reached....SSH session could not be established")
                return False
        except Exception,e:
            self.log.error("Exception occurred in ssh.py while opening connection ")
            self.log.error(e)
            return False


    """
    Desc:This method will close ssh connection"
    """
    def close_ssh_session(self):
        try:
            self.connection.close()
        except Exception,e:
            self.log.error("Exception occurred in ssh.py while closing connection ")
            self.log.error(e)
            return False

    """
    Desc:This method will execute command "
    """
    def execute_ssh_command(self, command, exp='#',timeout = 300000):
        try:
            #self.log.info("Executing command:  "+command)
            #if expect!='':
            #   exp=expect
            #else:
            #   exp = prompt_regex[self.type]
            self.connection.send(command)
            self.connection.send(line_delimiter[self.type])
            #expect = [pexpect.TIMEOUT, 'command not found', '% Invalid command.', "Aborted: application communication failure" ,"syntax error",exp]
            expect = [pexpect.TIMEOUT, 'command not found', '% Invalid command.', "Aborted: application communication failure" ,"syntax error",exp]
            index = self.connection.expect(expect, timeout)
            if  index == 0 :
                self.error_string = "SSH_TIMED_OUT"
                self.log.error("Timeout Reached.....")
                return False
            elif index == 1:
                self.error_string = "CMD_NOT_FOUND"
                self.log.error("Command Not Found: %s"%(command))
                return False
            elif index == 2:
                self.error_string = "INVALID_CMD"
                self.log.error("Invalid command: %s"%(command))
                return False
            elif index == 3:
                self.error_string = "Application Communication Failure"
                self.log.error("Application Communication Failure got for command: %s"%(command))
                return False
            elif index == 4:
                self.error_string = "syntax error"
                self.log.error("syntax error: unknown element got for command: %s"%(command))
                return False
            elif index == 5:
                self.log.info("Command executed successfully")
                self.log.debug("Command Output: %s %s" %(self.connection.before, self.connection.after))
                print "Executing command:  "+command
                return self.connection.before + self.connection.after
        except Exception,e:
            #print 'error while executing the cmd'
            #print "Exception occurred in ssh.py while executing command: "+command +"\n" + str(e)
            self.log.error("Exception occurred in ssh.py while executing command: "+command +"\n" + str(e))
            return False
        

    def get_ssh_handle(self):
        return self.connection

    def get_host_IP(self):
        return self.host

    def get_err_string(self):
        return self.error_string



