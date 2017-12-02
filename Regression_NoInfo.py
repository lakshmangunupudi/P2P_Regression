#!/usr/bin/env python



"""
Author:lgunupud@cisco.com
Date Created: 15th April-2015
Description: This class is used to execute command on linux machine and cae confd using ssh
"""


from ssh import *
from utilities import *
import logging
import sys
import re
import datetime
import time
import os.path
#from IPy import IP


starttime=datetime.datetime.now()

try:
     
     start_time=sys.argv[1]
     os.mkdir(results_path+start_time+'/')
     Utilities.init_logging(start_time)

     cae_shell=SSH("172.18.128.119", "staradmin", "Starent1" )
     cae_shell.open_ssh_session()
     
     ##callgen ssh object from where we will bring up the call
     callgen_shell=SSH("172.18.128.134", "root", "starent" )
     callgen_shell.open_ssh_session()
     
     ##pacer ssh object from where we will execute send data
     pacer_shell =SSH("172.18.128.134", "root", "starent" )
     pacer_shell.open_ssh_session()
      
     utils_obj=Utilities(cae_shell)
     utils_obj.config_p2p_nonp2p_rules()
     crash_output_init=cae_shell.execute_ssh_command('show crash list',exp="#")
     
     if "No crash record found" in crash_output_init:
	crash_init_count=0
     else:
	crash_init_count=int(crash_output_init.split("\n")[-3].split(":")[-1])	
     cae_shell.execute_ssh_command('debug shell card 1 cpu 0 ')
     cae_shell.execute_ssh_command('rm /records/edr/qqlive/*')
     cae_shell.execute_ssh_command('exit')
     
     
     protocol_nofolder_file=open(results_path+start_time+'/nofolder.csv','w+')
     for protocol in protocols_to_run:
          
          
          if(os.path.isdir('/home/pcap/Pcap-Repository/'+protocol)):  
               
               totalPcaps=pacer_shell.execute_ssh_command('find /home/pcap/Pcap-Repository/'+protocol +' -type f -name "*.pcap" -size +100c  -exec ls -lrt {} \; |tail -n '+str(number_of_pcaps_per_protocol)+'|awk \'{print $8}\'')
               totalProtocolPcaps=totalPcaps.split('\n')[1:-1]
               utils_obj.log.debug('\n\n protocol running is \n '+protocol)
               
               protocol_result_file=open(results_path+start_time+'/'+protocol+'.csv','w+')
               utils_obj.log.debug('totla pcaps are ----- > '+str(totalProtocolPcaps))
               for eachPcap in totalProtocolPcaps :
                  if os.path.isfile(str(eachPcap.strip())):
                           utils_obj.clearSubscribers()
                           finalPcap=eachPcap.strip() 
                           
                           Ip_out=pacer_shell.execute_ssh_command('tcpdump -nnr '+ finalPcap+'  -c 10000 |awk \'{print $3 "\\n" $5}\' |cut -d\'.\' -f1,2,3,4|sort|uniq -c|sort -nrk 1,1|head -n 1')
                           if re.search("bad dump file format",str(Ip_out)):
                              continue
                           Ip_address=str(Ip_out.split('\n')[2]).strip().split(' ')[1]
                  
                           
                           utils_obj.startPacerCall(callgen_shell)
                           time.sleep(5)
                           utils_obj.log.debug('\ncall is upppp and pcap name is  '+finalPcap+'  ip is '+Ip_address)
                           utils_obj.sendPcap(pacer_shell,finalPcap,Ip_address)
                           
                           utils_obj.log.debug('\nsent data pls check the stats\n')
                         
                           cae_shell.execute_ssh_command('clear active-charging flows all')
                             
                           ##here we are getting dictionary of per protocol
                           utils_obj.log.debug(cae_shell.execute_ssh_command('show active-charging analyzer statistics name p2p  application '+protocol+' verbose'))
                           analyser_stats=utils_obj.parseP2P_ProtocolAnalyserStats(protocol)
                           
                           utils_obj.log.debug(cae_shell.execute_ssh_command('show active-charging analyzer statistics name p2p wide')) 
                           ###getting fastpath stats
                           fast_path_dict=utils_obj.parseP2P_AnalyserWideStats()
        
                           ###getting per application/protocol stats
                           utils_obj.log.debug('\n total application packets are ')
                           app_up_down_link_pkts=analyser_stats[protocol]
                           
                           utils_obj.log.debug('\ntotal p2p applications up/down link stats are'+str(analyser_stats)+'\n')
                           total_up_down_app_pkts=int(app_up_down_link_pkts['Downlink Pkts'])+int(app_up_down_link_pkts['Uplink Pkts'])
                           
                       
                           
                           utils_obj.log.debug(cae_shell.execute_ssh_command('show active-charging analyzer statistics name p2p summary'))
                           p2p_summary_stats=utils_obj.parseP2P_AnalyserSummaryStats()
                           
                           utils_obj.log.debug(cae_shell.execute_ssh_command('show active-charging ruledef statistics all charging |grep [1-9]'))
                           
                           p2p_ruledef_stats=utils_obj.parseP2P_RuledefStats()
                           
                           utils_obj.log.debug('\ntotal p2p summary  up/down link stats are'+str(p2p_summary_stats)+'\n')
                           
                           utils_obj.log.debug(cae_shell.execute_ssh_command('show active-charging analyzer statistics name p2p verbose |grep [1-9]'))
                           p2p_analyser_stats=utils_obj.parseP2PAnalyserStats()
                           
                           ##Here we are calculating analyser packets
                           
                           sumofPackets=0
                           
                           for each_value in p2p_analyser_stats.values():
                               sumofPackets=sumofPackets+int(each_value['Downlink Pkts'])+int(each_value['Uplink Pkts'])
                               
                           utils_obj.log.debug('total analyser packets are'+str(sumofPackets))
                           
                           ##Here we are adding total p2p and non-p2p packets and then we will divide it with app stats.
                           
                           total_p2p_nonp2p_pkt=0
                           for keys in p2p_summary_stats.iterkeys():
                              for  subkey in p2p_summary_stats[keys].iterkeys():
                                  total_p2p_nonp2p_pkt+=int(p2p_summary_stats[keys][subkey]) 
                           
                           
                           utils_obj.log.debug('\ntotal up/down p2p and non-p2p  packets for this pcap are  '+str(total_p2p_nonp2p_pkt)+'\n')
                           
                           stats_check='Pass'
                           diff_in_p2p_stats=total_p2p_nonp2p_pkt-sumofPackets
                           if diff_in_p2p_stats>20:
                                stats_check='Fail'
                           
                           ##Decide whether test case is pass/fail
                           if total_p2p_nonp2p_pkt!=0:
                              perc=(total_up_down_app_pkts/float(total_p2p_nonp2p_pkt))*100
                           
                           else:
                              utils_obj.log.debug('please check the pcap  information '+eachPcap)
                              perc=0
                       
                           utils_obj.log.debug('\n\n percentage of app packets of this pcap are  -->'+str(perc))
                           
                           
                           protocol_result_file.write(str(perc)+"::"+eachPcap+"::"+str(p2p_summary_stats)+"::"+str(analyser_stats)+"::"+str(p2p_analyser_stats)+"::"+str(fast_path_dict)+"::"+str(p2p_ruledef_stats)+"::"+str(total_up_down_app_pkts)+"::"+str(total_p2p_nonp2p_pkt)+'\n')
                           
                           if perc>100.0:
                                  utils_obj.log.debug( '### Percentage cant be more than 100 please check something went wrong mostly in parsing  ###')
                                  sys.exit(1)
                                                       
               protocol_result_file.close()
               ##just collecting edr's after every protocols, assuming card 4 is active because it is only one for edrs
               cae_shell.execute_ssh_command('debug shell card 1 cpu 0 ')
               cae_shell.execute_ssh_command('scp /records/edr/qqlive/* card8-cpu0:/flash/sftp/edr/')
               cae_shell.execute_ssh_command('exit')
               
          
          else:
               
               utils_obj.log.debug('folder of this protocol is not there '+protocol)
               protocol_nofolder_file.write('folder of this protocol is not there '+protocol+' \n')
          
      
     protocol_nofolder_file.close()     
     crash_output_final=cae_shell.execute_ssh_command('show crash list')
     print crash_output_final
     if "No crash record found" in crash_output_final:
	crash_final_count=0
     else:
	crash_final_count=int(crash_output_final.split("\n")[-3].split(":")[-1])
     
     crashes_count=crash_final_count-crash_init_count
     if crashes_count > 0:
	utils_obj.log.debug("*************Crashes are seen.Check chassis for details **************************")
     else:
	utils_obj.log.debug("*****************************No Crashes***************************")
     
except Exception, e:
     utils_obj.log.debug('Unexpected error while initialising log'+str(sys.exc_info()[0])+str(e))

finally:
     cae_shell.close_ssh_session()
     callgen_shell.close_ssh_session()
     pacer_shell.close_ssh_session()
     stoptime=datetime.datetime.now()
exectime=stoptime-starttime
utils_obj.log.debug("************** Execution Time:"+str(exectime).split(".")[0]+"********************")
