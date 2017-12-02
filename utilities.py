#!/usr/bin/env python



"""
Author:lgunupud@cisco.com
Date Created: 15th April-2015
Description: This class is used to execute command on linux machine and cae confd using ssh
"""

import sys
import time
import os
import logging
from globalParameters import *
import re

class Utilities:

        def __init__(self,caeshell,servershell=''):
            try:
                self.caeShell=caeshell
                self.serverShell=servershell
                self.log=logging.getLogger()
            except Exception, e:
                print 'error while initialising the Utilities object',str(sys.exc_info()[0])+str(e)
        
        @staticmethod
        def init_logging(filename):
          try:
            #Utilities.remove_Log_file()
            DEFAULT_LOG_LEVEL = "DEBUG" 
            LOG_FORMAT = "%(asctime)s %(levelname)s : %(name)s : %(message)s"
            #self.filename=filename
            log_file = results_path+filename+'/'+filename+'RegressionTestLogs'
            log_level = DEFAULT_LOG_LEVEL
            """Initialzes logging and sets up console , file handlers"""
        
            log_lvl = { "DEBUG" : logging.DEBUG ,
                    "INFO"  : logging.INFO ,
                    "WARNING" : logging.WARNING ,
                    "ERROR" : logging.ERROR ,
                    "CRITICAL" : logging.CRITICAL
                  }
            
            effective_lvl = log_lvl.get(log_level,log_lvl[DEFAULT_LOG_LEVEL])
            formatter = logging.Formatter(LOG_FORMAT)
        
            logger = logging.getLogger()
            logger.setLevel(effective_lvl)
        
            file_hdlr = logging.FileHandler(log_file)
            file_hdlr.setFormatter(formatter)
            logger.addHandler(file_hdlr)
            console_hdlr = logging.StreamHandler(sys.stdout)
            console_hdlr.setFormatter(formatter)
            logger.addHandler(console_hdlr)
          except Exception,e:
            print 'Unexpected error while initialising',str(sys.exc_info()[0])+str(e)
            #self.log.debug('Unexpected error while initialising log'+str(sys.exc_info()[0])+str(e))  
          
        
        
        # show active-charging analyzer statistics name p2p verbose|grep - do this for sub-classification
        def parseP2P_ProtocolAnalyserStats(self,protocol):
            try:
                self.log.debug('In analyser function and executing p2p protocol '+protocol +' verbose stats')
                outPut=self.caeShell.execute_ssh_command(' show active-charging analyzer statistics name p2p application '+str(protocol)+' verbose')
                
                ##spliting output and removing the unwanted lines
                final_list_subClassification=outPut.split('\n')[3:-3]
                
                ##this dictionary fianlly will contain the subclassification and uplink and downlink packets in sub dictionary
                ##eg:{'Facebook': {'Downlink Pkts': '23', 'Uplink Pkts': '23'}, 'Facebook streaming-video': {'Downlink Pkts': '0', 'Uplink Pkts': '0'}, 'Facebook audio': {'Downlink Pkts': '0', 'Uplink Pkts': '0'},
                ##'Facebook unclassified': {'Downlink Pkts': '23', 'Uplink Pkts': '23'}}
                final_Dict_subClassification={}
                lengthOfsubList=len(final_list_subClassification)
                for i in range(lengthOfsubList-2):
                    if i%4==0:##I want only uplink and downlink packets not bytes so this division is giving that value.
                        temp_dict={}
                        
                        ##eg:    'Uplink Pkts': '23'
                        uplink_list=(' '.join((str(final_list_subClassification[i+2])[:-1]).split())).split('Total')[1:][0].split(':')
                        temp_dict[uplink_list[0].strip()]=uplink_list[1].strip()
                        
                        ##eg     'Downlink Pkts': '23'
                        downlink_list=(' '.join((str(final_list_subClassification[i+2])[:-1]).split())).split('Total')[1:][1].split(':')
                        temp_dict[downlink_list[0].strip()]=downlink_list[1].strip()
                    
                        ##here key will be  application sub-classification
                        final_Dict_subClassification.update({(str(final_list_subClassification[i].split(':')[0]).strip()).lower():temp_dict})
                        
                return  final_Dict_subClassification       
                #self.log.debug('\n\n\n uplink and downlink packets of application '+protocol+' and subclassification ---->\n\n\n'+str(final_Dict_subClassification ))       
            except Exception, e:
                 self.log.debug('Unexpected error while fetching p2p analyser stats per protocol '+str(sys.exc_info()[0])+str(e))  
                
        
        
         # show active-charging analyzer statistics name p2p verbose|grep - do this for sub-classification
        def parseP2PAnalyserStats(self):
            try:
                self.log.debug('In analyser function and executing p2p analyser verbose stats')
                
                outPut=self.caeShell.execute_ssh_command(' show active-charging analyzer statistics name p2p verbose |grep -v " 0"')
                time.sleep(8)
                ##spliting output and removing the unwanted lines
                final_list_subClassification=outPut.split('\n')[4:-3]
                #print 'final list isssss,',final_list_subClassification
                
                ##this dictionary fianlly will contain the subclassification and uplink and downlink packets in sub dictionary
                ##eg:{'Facebook': {'Downlink Pkts': '23', 'Uplink Pkts': '23'}, 'Facebook streaming-video': {'Downlink Pkts': '0', 'Uplink Pkts': '0'}, 'Facebook audio': {'Downlink Pkts': '0', 'Uplink Pkts': '0'},
                ##'Facebook unclassified': {'Downlink Pkts': '23', 'Uplink Pkts': '23'}}
                final_Dict_subClassification={}
                lengthOfsubList=len(final_list_subClassification)
                
                for i in range(lengthOfsubList-1):
                    key=str(final_list_subClassification[i].split(' ',1)[0]).strip()
                    key1=str(final_list_subClassification[i+1].split(' ',1)[0]).strip()
                    if key!='' and key1 == '':    
                        temp_dict={}
                        uplink_list=(' '.join((str(final_list_subClassification[i+1])[:-1]).split())).split(':')
                        
                        final_up_down_link_list=[junk.strip() for junk in uplink_list ]
                        
                        sub_up_down_list=str(final_up_down_link_list[1]).split(' ',1)
                        
                        if int(sub_up_down_list[0])!=0 and int(final_up_down_link_list[2])!=0:
                        
                            ##uplink
                            temp_dict[final_up_down_link_list[0]]=sub_up_down_list[0]
                            ##down link
                            temp_dict[sub_up_down_list[1]]=final_up_down_link_list[2]
                            
                            ##here key will be  application sub-classification
                            final_Dict_subClassification.update({key:temp_dict})
                           
                        
                self.log.info('\n\n\n uplink and downlink packets of p2p applications---->\n\n\n'+str(final_Dict_subClassification ))
                return final_Dict_subClassification
            except Exception, e:
                 self.log.debug('Unexpected error while fetching p2p analyser stats '+str(sys.exc_info()[0])+str(e))  
                
        
          # show active-charging analyzer statistics name p2p verbose|grep - do this for sub-classification
        def parseIP_ProtocolAnalyserStats(self):
            try:
                self.log.info('In analyser function and executing ip protocol stats')
                
                time.sleep(20)
                outPut=self.caeShell.execute_ssh_command(' show active-charging analyzer statistics name ip verbose ')
                
                ##spliting output and removing the unwanted lines
                ip_up_down_link_list=' '.join(str(outPut.split('\n')[4]).split()).split('Total')[1:]
                ip_up_down_link_list=[junk.strip() for junk in ip_up_down_link_list ]
                
                ip_up_link_list=ip_up_down_link_list[0].split(':')
                ip_down_link_list=ip_up_down_link_list[1].split(':')
                final_ip_dict={}
                final_ip_dict.update({ip_up_link_list[0]:ip_up_link_list[1]})
                final_ip_dict.update({ip_down_link_list[0]:ip_down_link_list[1]})
                 
                return final_ip_dict
                
                #self.log.debug('\n\n\n uplink and downlink packets IP protocol are---->\n\n\n'+str(final_ip_dict))
            
            except Exception, e:
                 self.log.debug('Unexpected error while fetching ip analyser stats '+str(sys.exc_info()[0])+str(e))  
                
        
        def parseP2P_AnalyserSummaryStats(self):
            try:
                
                self.log.debug('In analyser function and executing p2p summary stats')
                outPut=self.caeShell.execute_ssh_command(' show active-charging analyzer statistics name p2p summary ')
                
                ##spliting output and removing the unwanted lines
                final_P2P_Summary_list=outPut.split('\n')[3:-4] ### if 15.0 release it is 3 or else 4 
                #show active-charging analyzer statistics name p2p summary
                
                print 'final dict iss',final_P2P_Summary_list
                final_P2P_Summary_Dict={}
                lengthOfsubList=len(final_P2P_Summary_list)
                for i in range(lengthOfsubList-2):
                    if i%4==0:##I want only uplink and downlink packets not bytes so this division is giving that value.
                        temp_dict={}
                        
                        ##eg:    'Uplink Pkts': '23'
                        uplink_list=(' '.join((str(final_P2P_Summary_list[i+2])[:-1]).split())).split('Total')[1:][0].split(':')
                        temp_dict[uplink_list[0].strip()]=uplink_list[1].strip()
                        
                        ##eg     'Downlink Pkts': '23'
                        downlink_list=(' '.join((str(final_P2P_Summary_list[i+2])[:-1]).split())).split('Total')[1:][1].split(':')
                        temp_dict[downlink_list[0].strip()]=downlink_list[1].strip()
                    
                        ##here key will be  application sub-classification
                        final_P2P_Summary_Dict.update({(str(final_P2P_Summary_list[i].split(':')[0]).strip()).lower():temp_dict})         
                
                return final_P2P_Summary_Dict
                #self.log.info('\n\n\n P2P summary stats-----> \n\n\n---->'+str(final_P2P_Summary_Dict))

            except Exception, e:
                 self.log.debug('Unexpected error whileexecuting summary stats '+str(sys.exc_info()[0])+str(e))  
        
        
        def parseP2P_AnalyserWideStats(self):
            try:
                
                self.log.debug('In analyser function and executing p2p wide stats')
                outPut=self.caeShell.execute_ssh_command(' show active-charging analyzer statistics name p2p wide ') #in 15.0 release wide cli is not available 
                
                ##spliting output and removing the unwanted lines
                final_P2P_Wide_list=outPut.split('\n')[6:-3]
                self.log.debug('wide output issss'+str(final_P2P_Wide_list))
                
                final_P2P_Wide_Dict={}
                lengthOfsubList=len(final_P2P_Wide_list)
                
                for i in range(lengthOfsubList):
                        uplink_list=final_P2P_Wide_list[i].split()                
                        final_P2P_Wide_Dict[uplink_list[0].strip()]=uplink_list[5].strip()
                self.log.debug(final_P2P_Wide_Dict)
                return final_P2P_Wide_Dict
                
            except Exception, e:
                 self.log.debug('Unexpected error whileexecuting summary stats '+str(sys.exc_info()[0])+str(e))  
        
        
        def parseP2P_RuledefStats(self):
            try:
                
                
                self.log.debug('In ruledef function and executing p2p ruledef stats')
                outPut=self.caeShell.execute_ssh_command('show active-charging ruledef statistics all charging ')
            
                ##spliting output and removing the unwanted lines
                final_P2P_Wide_list=outPut.split('\n')[5:-3]
                final_P2P_Wide_Dict={}
                
                lengthOfsubList=len(final_P2P_Wide_list)
                
                for i in range(lengthOfsubList):
                        temp_dict={}
                        uplink_list=final_P2P_Wide_list[i].split()
                        temp_dict.update({"Packets-Down":uplink_list[1].strip()})
                        temp_dict.update({"Packets-Up":uplink_list[3].strip()})
                        temp_dict.update({"Hits":uplink_list[5].strip()})
                        temp_dict.update({"Match-Bypassed":uplink_list[6].strip()})
                        final_P2P_Wide_Dict[uplink_list[0].strip()]=temp_dict
                return final_P2P_Wide_Dict
                
            except Exception, e:
                 self.log.debug('Unexpected error whileexecuting ruledef stats '+str(sys.exc_info()[0])+str(e))  
        
        def config_p2p_nonp2p_rules(self):
            try:
                self.caeShell.execute_ssh_command('cli test-commands password boxer')
                self.caeShell.execute_ssh_command('config')
                self.caeShell.execute_ssh_command('timestamps')
                #self.caeShell.execute_ssh_command('no active-charging service '+acs_used)
                self.caeShell.execute_ssh_command('end')  
                self.log.debug(self.caeShell.execute_ssh_command('show version'))
                self.log.debug(self.caeShell.execute_ssh_command('show module p2p'))
                self.log.debug(self.caeShell.execute_ssh_command('show config|grep p2p'))
                self.log.debug(self.caeShell.execute_ssh_command('show boot'))
                self.log.debug(self.caeShell.execute_ssh_command('debug bang bash'))
                self.log.debug(self.caeShell.execute_ssh_command('rm -rf /flash/sftp/edr/'))
                self.log.debug(self.caeShell.execute_ssh_command('mkdir /flash/sftp/edr/'))
                self.log.debug(self.caeShell.execute_ssh_command('exit'))
                
                #self.caeShell.execute_ssh_command('config '+config_used)
                #time.sleep(100)
                
            except Exception, e:
                 self.log.debug('Unexpected error while initialising the rule '+str(sys.exc_info()[0])+str(e))
                 
                 
        def get_P2P_ruledef_Stats(self,ruleName):
            try:
                
                
                self.log.info('In ruledef function and executing p2p ruledef stats')
                
                final_ruledef_dict={}
                
                ##
                outPut=self.caeShell.execute_ssh_command(' show active-charging ruledef statistics name '+ruleName)
                final_ruledef_list=(' '.join(str(outPut.split('\n')[5]).split())).split(' ')
               
                
                ##for non p2p ruledef stats
                temp_dict={}
                temp_dict.update({'Uplink Pkts':final_ruledef_list[3]})
                temp_dict.update({'Downlink Pkts':final_ruledef_list[1]})
                final_ruledef_dict.update({ruleName:temp_dict})
                
                return final_ruledef_dict
                
                #self.log.debug('\n\n\n P2P ruledef  stats----->'+str(final_ruledef_dict))
                
            except Exception, e:
                 self.log.debug('Unexpected error while initialising the rule '+str(sys.exc_info()[0])+str(e))
                    
        
        def startPacerCall(self,callgenShell):
            try:
               
                callgenShell.execute_ssh_command(callGenTool+' -driver gtp -co -cod -gaddr 112.112.112.1 -saddr 112.112.112.2 -apn radius.com -drate 100 -gtp_sel_mode MS -ncc 1 -v 0 -iptun -imsi 404-270-00000001  -tunra 192.168.2.250 -daa  -tunrnm 255.255.255.0 -tunmc 1000 -pacer -np 1000000000 &')
                self.log.debug('##########  Started pacer call ############')
                self.log.debug(self.caeShell.execute_ssh_command('show subscribers all|grep radius.com'))
                time.sleep(3)
            except Exception, e:   
               self.log.debug('Unexpected error while bringing up the call '+str(sys.exc_info()[0])+str(e)) 
                
        def clearSubscribers(self):
            try:
                
                self.caeShell.execute_ssh_command('clear subscribers all')
                self.caeShell.execute_ssh_command('clear active-charging analyzer statistics')
                self.caeShell.execute_ssh_command('clear active-charging ruledef statistics')
                self.caeShell.execute_ssh_command('clear active-charging flows all')
                #self.caeShell.execute_ssh_command('config /flash/clear')
                time.sleep(2)
            except Exception, e:
                 self.log.debug('Unexpected error while clearing the call '+str(sys.exc_info()[0])+str(e))  
                
                
        def sendPcap(self,pacerShell,filename,ipAddress):
            try:
                pacerShell.execute_ssh_command(PacerTool+' -VV -M tun-0 -I eth2.789 -Q 00:05:00:00:00:08 -S -1 -FZ -b '+str(ipAddress)+' -f '+str(filename)+' -D 0 -T 50 -FK')
            except Exception, e:
                 self.log.debug('Unexpected error while initialising the rule '+str(sys.exc_info()[0])+str(e))

        def selectSmMgr(self):
            try:

                self.log.info('Identifying a SessMgr and redirecting all calls to it.')
                output=self.caeShell.execute_ssh_command('show task resources facility sessmgr all')
                pattern=re.compile(r"([0-9])/([0-9])\s+sessmgr\s+([0-9]+)\s+[0-9\s\.\%GM\-]+([SI])\s+([a-z]+)")
                inst=-1
                for line in output.split('\n'):
                    m=pattern.match(line.strip())
                    if (m):
                        card=m.group(1).strip()
                        cpu=m.group(2).strip()
                        mode=m.group(4).strip()
                        state=m.group(5).strip()
                        print ('SMgr Instance '+str(inst)+' card/cpu'+card+'/'+cpu+' with mode '+mode+' and state '+state)
                        if state == 'good' and mode == 'I':
                            inst=m.group(3).strip()
                            print "Coming here "+mode
                            break
                self.caeShell.execute_ssh_command('cli test-commands password boxer')
                if inst != -1:
                    self.caeShell.execute_ssh_command('select policy demuxmgr egtpinmgr sessmgr instance '+str(inst))
                    time.sleep(30)
                    heap=self.caeShell.execute_ssh_command('show messenger proclet facility sessmgr instance '+str(inst)+' heap depth 9',exp="bngnc18#")
                    time.sleep(2)
                    pattern=re.compile(r".*Heap Size:\s+([0-9]+)")
                    for line in heap.split('\n'):
                        m=pattern.match(line.strip())
                        if m:
                            self.log.debug('Heap Size before call: '+m.group(1).strip())
                            return m.group(1).strip(),inst
                    return 0,0
            except Exception, e:
                 self.log.debug('Unexpected error while selecting sessmgr '+str(sys.exc_info()[0])+str(e))

        def deselectSmMgr(self,inst):
            try:
                self.caeShell.execute_ssh_command('cli test-commands password boxer')
                time.sleep(60)
                self.caeShell.execute_ssh_command('no select policy demuxmgr egtpinmgr')
                heap=self.caeShell.execute_ssh_command('show messenger proclet facility sessmgr instance '+str(inst)+' heap depth 9',exp="bngnc18#")
                pattern=re.compile(r".*Heap Size:\s+([0-9]+)")
                for line in heap.split('\n'):
                    m=pattern.match(line.strip())
                    if m:
                        self.log.debug('Heap Size adter call: '+m.group(1).strip())
                        return m.group(1).strip()
                return 0
            except Exception, e:
                self.log.debug('Unexpected error while deselecting sessmgr '+str(sys.exc_info()[0])+str(e))

        def getProcletHeap(self,inst):
            try:
                self.caeShell.execute_ssh_command('cli test-commands password boxer')
                heap=self.caeShell.execute_ssh_command('show messenger proclet facility sessmgr instance '+str(inst)+' heap depth 9',exp="bngnc18#")
                pattern=re.compile(r".*Heap Size:\s+([0-9]+)")
                for line in heap.split('\n'):
                    m=pattern.match(line.strip())
                    if m:
                        self.log.debug('Heap Size adter call: '+m.group(1).strip())
                        return m.group(1).strip()
                return 0
            except Exception, e:
                self.log.debug('Unexpected error while deselecting sessmgr '+str(sys.exc_info()[0])+str(e)) 

