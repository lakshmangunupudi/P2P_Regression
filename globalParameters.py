#!/usr/bin/env python

PacerTool='/home/pcap/P2PRegression/tools/Pacer/pacer'
callGenTool='/home/pcap/P2PRegression/tools//Callgen/callgen_44890'
infoFilePath='/home/pcap/InfoFiles/'
results_path='/home/pcap/P2P/lakshman/regression/logs/'
number_of_pcaps_per_protocol    =50

config_used='/flash/sftp/working_18.3.cfg'
acs_used='service_1'

protocols_to_run=['sudaphone', 'svtplay', 'hyves', 'silverlight', 'blackdialer', 'rodi', 'skydrive', 'vtok', 'flickr', 'kuro', 'dropbox', 'heytell', 'bitcasa', 'clubbox',
                  'tumblr', 'youtube', 'voxer', 'hotspotvpn', 'baidumovie', 'badoo', 'vine', 'yahoomail', 'outlook', 'monkey3', 'foursquare', 'jap',
                  'applemaps', 'regram', 'bbm', 'chikka', 'box', 'imgur', 'oist',
                  'vchat', 'youku','cisco-jabber','waze','hls','lync','path','bittorrent-sync', 'behavioral-video', 'apple-store', 'samsung-store',
                  'blackberry-store', 'igo', 'mozy', 'mapfactor', 'opendrive', 'windows-azure', 'nokia-store', 'windows-store',
                  'navigon', 'weibo', 'hulu', 'telegram', 'didi', 'xing', 'kik-messenger', 'friendster', 'tagged', 'idrive', 'hike-messenger', 'google-music', 'apple-push',
                  'google-push', 'twitch', 'rhapsody', 'speedtest', 'upc-phone', 'iheartradio', 'hbogo', 'slacker-radio',
                  'radio-paradise', 'beatport', 'soundcloud', 'amazonmusic','ssl', 'slingtv', 'vessel', '8tracks', 'quic', 'tunein-radio', 'go90', 'vudu', 'periscope',
                  'hbonow', 'crackle', 'espn','amazonvideo', 'showtime', 'vevo', 'mlb', 'starz', 'tmo-tv', 'hgtv', 'nbc-sports',
                  'univision', 'dish-anywhere', 'fox-sports', 'newsy', 'fandor', 'odnoklassniki', 'http', 'kidoodle', 'mega', 'fubotv',
                  'wwe', 'curiosity-stream', 'dns-tunneling', 'fox-news',
                  'nbc-tv', 'redbulltv', 'tidal', 'directv', 'fox-business','pokemon-go','odkmedia','anyconnect','aenetworks',
                  'discord', 'playstation', 'fxnow', 'blackplanet_radio','klowdtv','accuradio', 'xfinity', 'natgeotv', 'fox-now',
                  'fandangonow', 'dailymotion', 'tennischannel', 'msoffice365', 'uber', 'esne', 'crunchyroll', 'deezer','spark', 'dramafever', 'yiptv', 'tinder',
                  'tvland', 'abcnetworks', 'spike', 'pbs', 'nick', 'yogafree', 'betternet','turbovpn', 'vpnmaster', 'expressvpn',
                  'hayu', 'disneymovies', 'filmontv', 'livestream', 'dpantv', 'mobcrush', 'tubitv', 'mikandi','http2','toongoggles',
                  '6play','bfmtv','mycanal','francetv','mytf','clashroyale']


'''
protocols_to_run=['skype', 'bittorrent', 'edonkey', 'msn', 'yahoo', 'orb', 'gnutella', 'jabber', 'slingbox', 'winny', 'fasttrack', 'manolito', 'pando', 'filetopia', 'soulseek', 'ppstream', 'qq', 'qqlive', 'mute', 'gadugadu', 'feidian', 'applejuice', 'zattoo','skinny',
                  'sopcast', 'ares', 'directconnect', 'imesh', 'pplive', 'oscar', 'popo', 'irc', 'steam', 'ddlink', 'halflife2', 'hamachivpn', 'tvants', 'tvuplayer', 'uusee', 'vpnx', 'vtun', 'winmx', 'wofwarcraft', 'xbox', 'iskoot', 'fring', 'oovoo', 'gtalk', 'freenet',
                  'aimini', 'battlefld', 'openft', 'qqgame', 'quake', 'secondlife', 'actsync', 'nimbuzz', 'iax', 'paltalk', 'warcft3', 'rdp', 'iptv', 'pandora', 'icecast', 'kontiki', 'meebo', 'shoutcast', 'truphone',
                  'thunder', 'armagettron', 'blackberry', 'citrix', 'clubpenguin', 'crossfire', 'dofus', 'fiesta', 'florensia', 'funshion', 'guildwars', 'isakmp', 'maplestory', 'mgcp', 'octoshape', 'off',
                  'ps3', 'rmstream', 'rfactor', 'splashfighter', 'ssdp', 'stealthnet','stun','teamspeak', 'tor', 'veohtv', 'wii', 'wmstream', 'wofkungfu', 'xdcc', 'yourfreetunnel', 'facebook', 'gamekit', 'facetime', 'gmail', 'itunes', 'myspace',
                  'teamviewer', 'twitter', 'viber', 'antsp2p', 'imo', 'netmotion', 'ogg', 'openvpn', 'quicktime', 'spotify', 'tango', 'ultrabac', 'usenet', 'tunnelvoice', 'scydo', 'whatsapp', 'flash',
                  'mojo', 'pcanywhere', 'mypeople', 'webex', 'netflix', 'implus', 'ebuddy', 'msrp', 'ficall', 'gotomeeting', 'mig33', 'comodounite', 'goober',
                  'iplayer', 'operamini', 'rdt', 'kakaotalk', 'nateontalk', 'naverline', 'callofduty', 'thunderhs', 'avi', 'wuala', 'wechat', 'soribada', 'icloud',
                  'googleplay', 'kugou', 'instagram', 'voipdiscount', 'vopium', 'plingm', 'pinterest', 'magicjack', 'spdy', 'amazoncloud', 'smartvoip', 'rynga','icall','actionvoip','jumblo','talkatone', 'mapi', 'behavioral-p2p', 'behavioral-voip', 'behavioral-upload',
                  'behavioral-download', 'imessage', 'linkedin', 'google', 'poco', 'ultrasurf', 'snapchat', 'truecaller', 'cyberghost', 'googleplus', 'adobeconnect',
                  'ustream', 'siri', 'softether', 'sudaphone', 'svtplay', 'hyves', 'silverlight', 'blackdialer', 'rodi', 'skydrive', 'vtok', 'flickr', 'kuro', 'dropbox', 'heytell', 'bitcasa', 'clubbox',
                  'tumblr', 'youtube', 'voxer', 'hotspotvpn', 'baidumovie', 'badoo', 'vine', 'yahoomail', 'outlook', 'monkey3', 'foursquare', 'jap', 'applemaps', 'regram', 'bbm', 'chikka', 'box', 'imgur', 'oist',
                  'vchat', 'youku', 'cisco-jabber', 'waze', 'hls', 'lync', 'path', 'bittorrent-sync', 'behavioral-video', 'apple-store', 'samsung-store',
                  'blackberry-store', 'igo', 'mozy', 'mapfactor', 'opendrive', 'windows-azure', 'nokia-store', 'windows-store',
                  'navigon', 'weibo', 'hulu', 'telegram', 'didi', 'xing', 'kik-messenger', 'friendster', 'tagged', 'idrive', 'hike-messenger', 'google-music', 'apple-push',
                  'google-push', 'twitch', 'rhapsody', 'speedtest', 'upc-phone', 'iheartradio', 'hbogo', 'slacker-radio',
                  'radio-paradise', 'beatport', 'soundcloud', 'amazonmusic','ssl', 'slingtv', 'vessel', '8tracks', 'quic', 'tunein-radio', 'go90', 'vudu', 'periscope',
                  'hbonow', 'crackle', 'espn', 'amazonvideo', 'showtime', 'vevo', 'mlb', 'starz', 'tmo-tv', 'hgtv', 'nbc-sports',
                  'univision', 'dish-anywhere', 'fox-sports', 'newsy', 'fandor', 'odnoklassniki', 'http', 'kidoodle', 'mega', 'fubotv', 'wwe', 'curiosity-stream', 'dns-tunneling', 'fox-news',
                  'nbc-tv', 'redbulltv', 'tidal', 'directv', 'fox-business', 'pokemon-go', 'odkmedia', 'anyconnect', 'aenetworks', 'discord', 'playstation', 'fxnow', 'blackplanet_radio', 'klowdtv', 'accuradio', 'xfinity', 'natgeotv', 'fox-now',
                  'fandangonow', 'dailymotion', 'tennischannel', 'msoffice365', 'uber', 'esne', 'crunchyroll', 'deezer','spark', 'dramafever', 'yiptv', 'tinder',
                  'tvland', 'abcnetworks', 'spike', 'pbs', 'nick', 'yogafree', 'betternet',
                  'turbovpn', 'vpnmaster', 'expressvpn', 'hayu', 'disneymovies', 'filmontv', 'livestream', 'dpantv', 'mobcrush', 'tubitv', 'mikandi','http2','toongoggles','6play','bfmtv','mycanal','francetv','mytf','clashroyale']
'''