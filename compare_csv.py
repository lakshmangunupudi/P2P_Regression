#!/usr/bin/env python
import sys
import os


protocol_list=['dns-tunneling', 'fox-news',
                  'nbc-tv', 'redbulltv', 'tidal', 'directv', 'fox-business','pokemon-go','odkmedia','anyconnect','aenetworks',
                  'discord', 'playstation']
new_list=sys.argv[1]
old_list=sys.argv[2]

for each_protocol in protocol_list:
        
        count1=0
        if os.path.isfile('/home/pcap/P2P/lakshman/regression/logs/'+old_list+'/'+each_protocol+'.csv') and os.path.isfile('/home/pcap/P2P/lakshman/regression/logs/'+new_list+'/'+each_protocol+'.csv'):
                file_obj_base=open('/home/pcap/P2P/lakshman/regression/logs/'+old_list+'/'+each_protocol+'.csv','r+')
                
                file_obj_current=open('/home/pcap/P2P/lakshman/regression/logs/'+new_list+'/'+each_protocol+'.csv','r+')
                
                orig_dict={}
                current_dict={}
                pcap_list=file_obj_base.read().split('\n')
                
                for line in pcap_list[:-1]:
                        list1= str(line).split('::')
                      
                        #print list1[0],list1[2]
                        #print list1[1].strip(),list1[0]
                        orig_dict.update({list1[1].strip():list1[0]})
                
                 
                pcap_list=file_obj_current.read().split('\n')
                for line in pcap_list[:-1]:
                        list1= str(line).split('::')
                        current_dict.update({list1[1].strip():list1[0]})
                 
                
                issues=0
                for keys in orig_dict.iterkeys():
                      if current_dict.has_key(keys):
                        
                        if float(orig_dict[keys])-float(current_dict[keys])>1.0:
                               #if float(orig_dict[keys])==0.0:
                                  print ''+keys,float(orig_dict[keys])-float(current_dict[keys])
                                  issues=1
                if issues==0:
                        print 'no issues  found in regression',each_protocol
              
        else:
        	print("No "+each_protocol)
