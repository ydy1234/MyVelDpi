/*

	Don't edit this file!

	source file: ndpi_network_list_std.yaml

 */

ndpi_network host_protocol_list[] = {
  /*
    BITTORRENT
   */
  { 0x05277C26, 32 , NDPI_PROTOCOL_BITTORRENT /* 5.39.124.38        */  },
  { 0x25779CBD, 32 , NDPI_PROTOCOL_BITTORRENT /* 37.119.156.189     */  },
  { 0x4DDEAE14, 32 , NDPI_PROTOCOL_BITTORRENT /* 77.222.174.20      */  },
  { 0x4FC0AB43, 32 , NDPI_PROTOCOL_BITTORRENT /* 79.192.171.67      */  },
  { 0xAC100010, 32 , NDPI_PROTOCOL_BITTORRENT /* 172.16.0.16        */  },
  { 0xAE597B3E, 32 , NDPI_PROTOCOL_BITTORRENT /* 174.89.123.62      */  },
  { 0xB2A4F550, 32 , NDPI_PROTOCOL_BITTORRENT /* 178.164.245.80     */  },
  { 0xB9381424, 32 , NDPI_PROTOCOL_BITTORRENT /* 185.56.20.36       */  },
  { 0xC0DEED0A, 32 , NDPI_PROTOCOL_BITTORRENT /* 192.222.237.10     */  },
  /*
    Valve Corporation (Steam)
    origin AS32590
   */
  { 0x2D79B800, 22 , NDPI_PROTOCOL_STEAM /* 45.121.184.0/22    */  },
  { 0x670A7C00, 23 , NDPI_PROTOCOL_STEAM /* 103.10.124.0/23    */  },
  { 0x671C3600, 23 , NDPI_PROTOCOL_STEAM /* 103.28.54.0/23     */  },
  { 0x8F899200, 24 , NDPI_PROTOCOL_STEAM /* 143.137.146.0/24   */  },
  { 0x92429800, 21 , NDPI_PROTOCOL_STEAM /* 146.66.152.0/21    */  },
  { 0x99FE5600, 24 , NDPI_PROTOCOL_STEAM /* 153.254.86.0/24    */  },
  { 0x9B85E000, 19 , NDPI_PROTOCOL_STEAM /* 155.133.224.0/19   */  },
  { 0xA2FEC000, 21 , NDPI_PROTOCOL_STEAM /* 162.254.192.0/21   */  },
  { 0xB919B400, 22 , NDPI_PROTOCOL_STEAM /* 185.25.180.0/22    */  },
  { 0xBED87900, 24 , NDPI_PROTOCOL_STEAM /* 190.216.121.0/24   */  },
  { 0xBED92100, 24 , NDPI_PROTOCOL_STEAM /* 190.217.33.0/24    */  },
  { 0xC0456000, 22 , NDPI_PROTOCOL_STEAM /* 192.69.96.0/22     */  },
  { 0xCDB9C200, 24 , NDPI_PROTOCOL_STEAM /* 205.185.194.0/24   */  },
  { 0xCDC40600, 24 , NDPI_PROTOCOL_STEAM /* 205.196.6.0/24     */  },
  { 0xD040C800, 22 , NDPI_PROTOCOL_STEAM /* 208.64.200.0/22    */  },
  { 0xD040C800, 24 , NDPI_PROTOCOL_STEAM /* 208.64.200.0/24    */  },
  { 0xD04EA400, 22 , NDPI_PROTOCOL_STEAM /* 208.78.164.0/22    */  },
  /*
    Facebook, Inc.
    origin AS32934, AS54115
   */
  { 0x1F0D1800, 21 , NDPI_SERVICE_FACEBOOK /* 31.13.24.0/21      */  },
  { 0x1F0D4000, 18 , NDPI_SERVICE_FACEBOOK /* 31.13.64.0/18      */  },
  { 0x2D402800, 22 , NDPI_SERVICE_FACEBOOK /* 45.64.40.0/22      */  },
  { 0x42DC9000, 20 , NDPI_SERVICE_FACEBOOK /* 66.220.144.0/20    */  },
  { 0x453FB000, 20 , NDPI_SERVICE_FACEBOOK /* 69.63.176.0/20     */  },
  { 0x45ABE000, 19 , NDPI_SERVICE_FACEBOOK /* 69.171.224.0/19    */  },
  { 0x4A774C00, 22 , NDPI_SERVICE_FACEBOOK /* 74.119.76.0/22     */  },
  { 0x67046000, 22 , NDPI_SERVICE_FACEBOOK /* 103.4.96.0/22      */  },
  { 0x81860000, 16 , NDPI_SERVICE_FACEBOOK /* 129.134.0.0/16     */  },
  { 0x9DF00000, 16 , NDPI_SERVICE_FACEBOOK /* 157.240.0.0/16     */  },
  { 0xADFC4000, 18 , NDPI_SERVICE_FACEBOOK /* 173.252.64.0/18    */  },
  { 0xB33CC000, 22 , NDPI_SERVICE_FACEBOOK /* 179.60.192.0/22    */  },
  { 0xB93CD800, 22 , NDPI_SERVICE_FACEBOOK /* 185.60.216.0/22    */  },
  { 0xC7C94000, 22 , NDPI_SERVICE_FACEBOOK /* 199.201.64.0/22    */  },
  { 0xCC0F1400, 22 , NDPI_SERVICE_FACEBOOK /* 204.15.20.0/22     */  },
  /*
    Twitter Inc.
    origin AS13414, AS35995
   */
  { 0x0819C200, 23 , NDPI_SERVICE_TWITTER /* 8.25.194.0/23      */  },
  { 0x0819C400, 23 , NDPI_SERVICE_TWITTER /* 8.25.196.0/23      */  },
  { 0x450C3800, 21 , NDPI_SERVICE_TWITTER /* 69.12.56.0/21      */  },
  { 0x67FC7000, 22 , NDPI_SERVICE_TWITTER /* 103.252.112.0/22   */  },
  { 0x68F42800, 21 , NDPI_SERVICE_TWITTER /* 104.244.40.0/21    */  },
  { 0xB92D0400, 22 , NDPI_SERVICE_TWITTER /* 185.45.4.0/22      */  },
  { 0xBC40E000, 21 , NDPI_SERVICE_TWITTER /* 188.64.224.0/21    */  },
  { 0xC02C4400, 23 , NDPI_SERVICE_TWITTER /* 192.44.68.0/23     */  },
  { 0xC030EC00, 23 , NDPI_SERVICE_TWITTER /* 192.48.236.0/23    */  },
  { 0xC0854C00, 22 , NDPI_SERVICE_TWITTER /* 192.133.76.0/22    */  },
  { 0xC7109C00, 22 , NDPI_SERVICE_TWITTER /* 199.16.156.0/22    */  },
  { 0xC73B9400, 22 , NDPI_SERVICE_TWITTER /* 199.59.148.0/22    */  },
  { 0xC7453A00, 23 , NDPI_SERVICE_TWITTER /* 199.69.58.0/23     */  },
  { 0xC7603800, 21 , NDPI_SERVICE_TWITTER /* 199.96.56.0/21     */  },
  { 0xCAA08000, 22 , NDPI_SERVICE_TWITTER /* 202.160.128.0/22   */  },
  /*
    Dropbox, Inc.
    origin AS19679
   */
  { 0x2D3A4000, 20 , NDPI_PROTOCOL_DROPBOX /* 45.58.64.0/20      */  },
  { 0x6CA0A000, 20 , NDPI_PROTOCOL_DROPBOX /* 108.160.160.0/20   */  },
  { 0xA27D0000, 16 , NDPI_PROTOCOL_DROPBOX /* 162.125.0.0/16     */  },
  { 0xB92D0800, 22 , NDPI_PROTOCOL_DROPBOX /* 185.45.8.0/22      */  },
  { 0xC72FD800, 22 , NDPI_PROTOCOL_DROPBOX /* 199.47.216.0/22    */  },
  /*
    Skype (Microsoft CDN)
   */
  { 0x0D400000, 11 , NDPI_PROTOCOL_SKYPE /* 13.64.0.0/11       */  },
  { 0x0D6B0380, 31 , NDPI_PROTOCOL_SKYPE /* 13.107.3.128/31    */  },
  { 0x17600000, 13 , NDPI_PROTOCOL_SKYPE /* 23.96.0.0/13       */  },
  { 0x287F816D, 32 , NDPI_PROTOCOL_SKYPE /* 40.127.129.109     */  },
  { 0x4237DF00, 26 , NDPI_PROTOCOL_SKYPE /* 66.55.223.0/26     */  },
  { 0x5BBED800, 21 , NDPI_PROTOCOL_SKYPE /* 91.190.216.0/21    */  },
  { 0x5BBEDA00, 24 , NDPI_PROTOCOL_SKYPE /* 91.190.218.0/24    */  },
  { 0x6FDD4000, 18 , NDPI_PROTOCOL_SKYPE /* 111.221.64.0/18    */  },
  { 0x9D360000, 15 , NDPI_PROTOCOL_SKYPE /* 157.54.0.0/15      */  },
  { 0x9D383400, 26 , NDPI_PROTOCOL_SKYPE /* 157.56.52.0/26     */  },
  { 0x9D383580, 25 , NDPI_PROTOCOL_SKYPE /* 157.56.53.128/25   */  },
  { 0x9D388740, 26 , NDPI_PROTOCOL_SKYPE /* 157.56.135.64/26   */  },
  { 0x9D38B900, 26 , NDPI_PROTOCOL_SKYPE /* 157.56.185.0/26    */  },
  { 0x9D38C600, 26 , NDPI_PROTOCOL_SKYPE /* 157.56.198.0/26    */  },
  { 0x9D3C0000, 16 , NDPI_PROTOCOL_SKYPE /* 157.60.0.0/16      */  },
  /*
    Google Inc. / Google Switzerland GmbH / Google Ireland Limited
    origin AS15169, AS36384, AS41264, AS43515, AS36039, AS36040, AS36492
   */
  { 0x08063000, 21 , NDPI_SERVICE_GOOGLE /* 8.6.48.0/21        */  },
  { 0x08080400, 24 , NDPI_SERVICE_GOOGLE /* 8.8.4.0/24         */  },
  { 0x08080800, 24 , NDPI_SERVICE_GOOGLE /* 8.8.8.0/24         */  },
  { 0x080FCA00, 24 , NDPI_SERVICE_GOOGLE /* 8.15.202.0/24      */  },
  { 0x0822D000, 20 , NDPI_SERVICE_GOOGLE /* 8.34.208.0/20      */  },
  { 0x0823C000, 20 , NDPI_SERVICE_GOOGLE /* 8.35.192.0/20      */  },
  { 0x17EC3000, 20 , NDPI_SERVICE_GOOGLE /* 23.236.48.0/20     */  },
  { 0x17FB8000, 19 , NDPI_SERVICE_GOOGLE /* 23.251.128.0/19    */  },
  { 0x23B80000, 13 , NDPI_SERVICE_GOOGLE /* 35.184.0.0/13      */  },
  { 0x2D79E400, 22 , NDPI_SERVICE_GOOGLE /* 45.121.228.0/22    */  },
  { 0x2E1CF700, 24 , NDPI_SERVICE_GOOGLE /* 46.28.247.0/24     */  },
  { 0x4009E000, 19 , NDPI_SERVICE_GOOGLE /* 64.9.224.0/19      */  },
  { 0x400F7000, 20 , NDPI_SERVICE_GOOGLE /* 64.15.112.0/20     */  },
  { 0x40E9A000, 19 , NDPI_SERVICE_GOOGLE /* 64.233.160.0/19    */  },
  { 0x42660000, 20 , NDPI_SERVICE_GOOGLE /* 66.102.0.0/20      */  },
  { 0x42F94000, 19 , NDPI_SERVICE_GOOGLE /* 66.249.64.0/19     */  },
  { 0x46208000, 19 , NDPI_SERVICE_GOOGLE /* 70.32.128.0/19     */  },
  { 0x480EC000, 18 , NDPI_SERVICE_GOOGLE /* 72.14.192.0/18     */  },
  { 0x4A721800, 21 , NDPI_SERVICE_GOOGLE /* 74.114.24.0/21     */  },
  { 0x4A7D0000, 16 , NDPI_SERVICE_GOOGLE /* 74.125.0.0/16      */  },
  { 0x59CFE000, 21 , NDPI_SERVICE_GOOGLE /* 89.207.224.0/21    */  },
  { 0x673E4000, 22 , NDPI_SERVICE_GOOGLE /* 103.62.64.0/22     */  },
  { 0x68840000, 14 , NDPI_SERVICE_GOOGLE /* 104.132.0.0/14     */  },
  { 0x689A0000, 15 , NDPI_SERVICE_GOOGLE /* 104.154.0.0/15     */  },
  { 0x68C40000, 14 , NDPI_SERVICE_GOOGLE /* 104.196.0.0/14     */  },
  { 0x68EDA000, 19 , NDPI_SERVICE_GOOGLE /* 104.237.160.0/19   */  },
  { 0x6BA7A000, 19 , NDPI_SERVICE_GOOGLE /* 107.167.160.0/19   */  },
  { 0x6BB2C000, 18 , NDPI_SERVICE_GOOGLE /* 107.178.192.0/18   */  },
  { 0x6C3B5000, 20 , NDPI_SERVICE_GOOGLE /* 108.59.80.0/20     */  },
  { 0x6CAAC000, 18 , NDPI_SERVICE_GOOGLE /* 108.170.192.0/18   */  },
  { 0x6CB10000, 17 , NDPI_SERVICE_GOOGLE /* 108.177.0.0/17     */  },
  { 0x71C56800, 22 , NDPI_SERVICE_GOOGLE /* 113.197.104.0/22   */  },
  { 0x82D30000, 16 , NDPI_SERVICE_GOOGLE /* 130.211.0.0/16     */  },
  { 0x8EFA0000, 15 , NDPI_SERVICE_GOOGLE /* 142.250.0.0/15     */  },
  { 0x92940000, 17 , NDPI_SERVICE_GOOGLE /* 146.148.0.0/17     */  },
  { 0xA2D89400, 22 , NDPI_SERVICE_GOOGLE /* 162.216.148.0/22   */  },
  { 0xA2DEB000, 21 , NDPI_SERVICE_GOOGLE /* 162.222.176.0/21   */  },
  { 0xAC660800, 21 , NDPI_SERVICE_GOOGLE /* 172.102.8.0/21     */  },
  { 0xAC6E2000, 21 , NDPI_SERVICE_GOOGLE /* 172.110.32.0/21    */  },
  { 0xACD90000, 16 , NDPI_SERVICE_GOOGLE /* 172.217.0.0/16     */  },
  { 0xACFD0000, 16 , NDPI_SERVICE_GOOGLE /* 172.253.0.0/16     */  },
  { 0xADC20000, 16 , NDPI_SERVICE_GOOGLE /* 173.194.0.0/16     */  },
  { 0xADFF7000, 20 , NDPI_SERVICE_GOOGLE /* 173.255.112.0/20   */  },
  { 0xB9191C00, 22 , NDPI_SERVICE_GOOGLE /* 185.25.28.0/22     */  },
  { 0xB9969400, 22 , NDPI_SERVICE_GOOGLE /* 185.150.148.0/22   */  },
  { 0xC068A000, 23 , NDPI_SERVICE_GOOGLE /* 192.104.160.0/23   */  },
  { 0xC0771C00, 24 , NDPI_SERVICE_GOOGLE /* 192.119.28.0/24    */  },
  { 0xC09E1C00, 22 , NDPI_SERVICE_GOOGLE /* 192.158.28.0/22    */  },
  { 0xC0B20000, 15 , NDPI_SERVICE_GOOGLE /* 192.178.0.0/15     */  },
  { 0xC1210400, 23 , NDPI_SERVICE_GOOGLE /* 193.33.4.0/23      */  },
  { 0xC1C8DE00, 24 , NDPI_SERVICE_GOOGLE /* 193.200.222.0/24   */  },
  { 0xC27A5000, 22 , NDPI_SERVICE_GOOGLE /* 194.122.80.0/22    */  },
  { 0xC7C07000, 22 , NDPI_SERVICE_GOOGLE /* 199.192.112.0/22   */  },
  { 0xC7DFE800, 21 , NDPI_SERVICE_GOOGLE /* 199.223.232.0/21   */  },
  { 0xCFDFA000, 20 , NDPI_SERVICE_GOOGLE /* 207.223.160.0/20   */  },
  { 0xD0419800, 22 , NDPI_SERVICE_GOOGLE /* 208.65.152.0/22    */  },
  { 0xD075E000, 19 , NDPI_SERVICE_GOOGLE /* 208.117.224.0/19   */  },
  { 0xD1558000, 17 , NDPI_SERVICE_GOOGLE /* 209.85.128.0/17    */  },
  { 0xD16BB000, 20 , NDPI_SERVICE_GOOGLE /* 209.107.176.0/20   */  },
  { 0xD83AC000, 19 , NDPI_SERVICE_GOOGLE /* 216.58.192.0/19    */  },
  { 0xD8495000, 20 , NDPI_SERVICE_GOOGLE /* 216.73.80.0/20     */  },
  { 0xD8EF2000, 19 , NDPI_SERVICE_GOOGLE /* 216.239.32.0/19    */  },
  { 0xD8FCDC00, 22 , NDPI_SERVICE_GOOGLE /* 216.252.220.0/22   */  },
  /*
    Netflix Inc. / Netflix Streaming Services Inc.
    origin AS2906, AS55095, AS40027
   */
  { 0x17F60000, 18 , NDPI_SERVICE_NETFLIX /* 23.246.0.0/18      */  },
  { 0x254DB800, 21 , NDPI_SERVICE_NETFLIX /* 37.77.184.0/21     */  },
  { 0x26487E00, 24 , NDPI_SERVICE_NETFLIX /* 38.72.126.0/24     */  },
  { 0x2D390000, 17 , NDPI_SERVICE_NETFLIX /* 45.57.0.0/17       */  },
  { 0x40788000, 17 , NDPI_SERVICE_NETFLIX /* 64.120.128.0/17    */  },
  { 0x42C58000, 17 , NDPI_SERVICE_NETFLIX /* 66.197.128.0/17    */  },
  { 0x4535E000, 19 , NDPI_SERVICE_NETFLIX /* 69.53.224.0/19     */  },
  { 0x6CAF2000, 20 , NDPI_SERVICE_NETFLIX /* 108.175.32.0/20    */  },
  { 0xB902DC00, 22 , NDPI_SERVICE_NETFLIX /* 185.2.220.0/22     */  },
  { 0xB909BC00, 22 , NDPI_SERVICE_NETFLIX /* 185.9.188.0/22     */  },
  { 0xC0AD4000, 18 , NDPI_SERVICE_NETFLIX /* 192.173.64.0/18    */  },
  { 0xC6266000, 19 , NDPI_SERVICE_NETFLIX /* 198.38.96.0/19     */  },
  { 0xC62D3000, 20 , NDPI_SERVICE_NETFLIX /* 198.45.48.0/20     */  },
  { 0xD04B4C00, 22 , NDPI_SERVICE_NETFLIX /* 208.75.76.0/22     */  },
  /*
    Citrix GotoMeeting (AS16815, AS21866)
   */
  { 0xD873D000, 20 , NDPI_PROTOCOL_CITRIX_ONLINE /* 216.115.208.0/20   */  },
  { 0xD8DB7000, 20 , NDPI_PROTOCOL_CITRIX_ONLINE /* 216.219.112.0/20   */  },
  /*
    Apple Inc.
    origin AS714, AS6185
   */
  { 0x11000000, 8 , NDPI_SERVICE_APPLE /* 17.0.0.0/8         */  },
  { 0xC0233200, 24 , NDPI_SERVICE_APPLE /* 192.35.50.0/24     */  },
  { 0xC6B71000, 23 , NDPI_SERVICE_APPLE /* 198.183.16.0/23    */  },
  { 0xCDB4AF00, 24 , NDPI_SERVICE_APPLE /* 205.180.175.0/24   */  },
  /*
    Cisco Webex LLC
    origin AS13445
   */
  { 0x0819C000, 24 , NDPI_PROTOCOL_WEBEX /* 8.25.192.0/24      */  },
  { 0x3E6DC000, 18 , NDPI_PROTOCOL_WEBEX /* 62.109.192.0/18    */  },
  { 0x40446000, 19 , NDPI_PROTOCOL_WEBEX /* 64.68.96.0/19      */  },
  { 0x4272A000, 20 , NDPI_PROTOCOL_WEBEX /* 66.114.160.0/20    */  },
  { 0x42A32000, 19 , NDPI_PROTOCOL_WEBEX /* 66.163.32.0/19     */  },
  { 0x721DC000, 19 , NDPI_PROTOCOL_WEBEX /* 114.29.192.0/19    */  },
  { 0xADF30000, 20 , NDPI_PROTOCOL_WEBEX /* 173.243.0.0/20     */  },
  { 0xCFB6A000, 19 , NDPI_PROTOCOL_WEBEX /* 207.182.160.0/19   */  },
  { 0xD0085100, 24 , NDPI_PROTOCOL_WEBEX /* 208.8.81.0/24      */  },
  { 0xD1C5C000, 19 , NDPI_PROTOCOL_WEBEX /* 209.197.192.0/19   */  },
  { 0xD204C000, 20 , NDPI_PROTOCOL_WEBEX /* 210.4.192.0/20     */  },
  /*
    WhatsApp Inc.
   */
  { 0x3216C6CC, 30 , NDPI_SERVICE_WHATSAPP /* 50.22.198.204/30   */  },
  { 0x4B7E2720, 27 , NDPI_SERVICE_WHATSAPP /* 75.126.39.32/27    */  },
  { 0x6CA8B460, 27 , NDPI_SERVICE_WHATSAPP /* 108.168.180.96/27  */  },
  { 0x9E553A00, 25 , NDPI_SERVICE_WHATSAPP /* 158.85.58.0/25     */  },
  { 0x9E55FE40, 27 , NDPI_SERVICE_WHATSAPP /* 158.85.254.64/27   */  },
  { 0xA92F2320, 27 , NDPI_SERVICE_WHATSAPP /* 169.47.35.32/27    */  },
  { 0xA93743E0, 27 , NDPI_SERVICE_WHATSAPP /* 169.55.67.224/27   */  },
  { 0xA93764A0, 27 , NDPI_SERVICE_WHATSAPP /* 169.55.100.160/27  */  },
  { 0xA937EBA0, 27 , NDPI_SERVICE_WHATSAPP /* 169.55.235.160/27  */  },
  { 0xADC0A220, 27 , NDPI_SERVICE_WHATSAPP /* 173.192.162.32/27  */  },
  { 0xB8AD8840, 27 , NDPI_SERVICE_WHATSAPP /* 184.173.136.64/27  */  },
  { 0xB93CDA20, 27 , NDPI_SERVICE_WHATSAPP /* 185.60.218.32/27   */  },
  { 0xC60BFB20, 27 , NDPI_SERVICE_WHATSAPP /* 198.11.251.32/27   */  },
  { 0xD02B73C0, 27 , NDPI_SERVICE_WHATSAPP /* 208.43.115.192/27  */  },
  { 0xD02B7A80, 27 , NDPI_SERVICE_WHATSAPP /* 208.43.122.128/27  */  },
  /*
    Viber Media S.à r.l.
    https://whois.arin.net/rest/nets;q=AWS-VIBER-MEDIA?showDetails=true&showARIN=false&showNonArinTopLevelNet=false&ext=netref2
   */
  { 0x3400FC00, 22 , NDPI_PROTOCOL_VIBER /* 52.0.252.0/22      */  },
  { 0x3640BFF0, 28 , NDPI_PROTOCOL_VIBER /* 54.64.191.240/28   */  },
  { 0x36A5FFD0, 28 , NDPI_PROTOCOL_VIBER /* 54.165.255.208/28  */  },
  { 0x36A5FFE0, 27 , NDPI_PROTOCOL_VIBER /* 54.165.255.224/27  */  },
  { 0x36A93FA0, 27 , NDPI_PROTOCOL_VIBER /* 54.169.63.160/27   */  },
  { 0x36A93FC0, 26 , NDPI_PROTOCOL_VIBER /* 54.169.63.192/26   */  },
  { 0x36DBBFA0, 28 , NDPI_PROTOCOL_VIBER /* 54.219.191.160/28  */  },
  { 0x36E8FB90, 28 , NDPI_PROTOCOL_VIBER /* 54.232.251.144/28  */  },
  /*
    Teamviewer
   */
  { 0x9F7AB800, 21 , NDPI_PROTOCOL_TEAMVIEWER /* 159.122.184.0/21   */  },
  /*
    Canonical Ltd (Ubuntu)
    origin AS41231
   */
  { 0x5BBD5800, 21 , NDPI_PROTOCOL_UBUNTUONE /* 91.189.88.0/21     */  },
  { 0xA2D52000, 22 , NDPI_PROTOCOL_UBUNTUONE /* 162.213.32.0/22    */  },
  { 0xB97DBC00, 22 , NDPI_PROTOCOL_UBUNTUONE /* 185.125.188.0/22   */  },
  /*
    Amazon.com, Inc. / Amazon Data Services Ireland Ltd
    origin AS16509, AS14618, AS7224, AS62785, AS8987
   */
  { 0x08129000, 23 , NDPI_SERVICE_AMAZON /* 8.18.144.0/23      */  },
  { 0x0D200000, 14 , NDPI_SERVICE_AMAZON /* 13.32.0.0/14       */  },
  { 0x0D340000, 14 , NDPI_SERVICE_AMAZON /* 13.52.0.0/14       */  },
  { 0x0D380000, 14 , NDPI_SERVICE_AMAZON /* 13.56.0.0/14       */  },
  { 0x0D700000, 14 , NDPI_SERVICE_AMAZON /* 13.112.0.0/14      */  },
  { 0x0D7C0000, 14 , NDPI_SERVICE_AMAZON /* 13.124.0.0/14      */  },
  { 0x0DD00000, 14 , NDPI_SERVICE_AMAZON /* 13.208.0.0/14      */  },
  { 0x0DE40000, 14 , NDPI_SERVICE_AMAZON /* 13.228.0.0/14      */  },
  { 0x0DE80000, 13 , NDPI_SERVICE_AMAZON /* 13.232.0.0/13      */  },
  { 0x0DF80000, 14 , NDPI_SERVICE_AMAZON /* 13.248.0.0/14      */  },
  { 0x17140000, 14 , NDPI_SERVICE_AMAZON /* 23.20.0.0/14       */  },
  { 0x1B000000, 22 , NDPI_SERVICE_AMAZON /* 27.0.0.0/22        */  },
  { 0x22C00000, 10 , NDPI_SERVICE_AMAZON /* 34.192.0.0/10      */  },
  { 0x23980000, 13 , NDPI_SERVICE_AMAZON /* 35.152.0.0/13      */  },
  { 0x23B00000, 13 , NDPI_SERVICE_AMAZON /* 35.176.0.0/13      */  },
  { 0x2BFAC000, 23 , NDPI_SERVICE_AMAZON /* 43.250.192.0/23    */  },
  { 0x2E338000, 18 , NDPI_SERVICE_AMAZON /* 46.51.128.0/18     */  },
  { 0x2E33C000, 20 , NDPI_SERVICE_AMAZON /* 46.51.192.0/20     */  },
  { 0x2E33D800, 21 , NDPI_SERVICE_AMAZON /* 46.51.216.0/21     */  },
  { 0x2E33E000, 19 , NDPI_SERVICE_AMAZON /* 46.51.224.0/19     */  },
  { 0x2E890000, 16 , NDPI_SERVICE_AMAZON /* 46.137.0.0/16      */  },
  { 0x32100000, 14 , NDPI_SERVICE_AMAZON /* 50.16.0.0/14       */  },
  { 0x32700000, 16 , NDPI_SERVICE_AMAZON /* 50.112.0.0/16      */  },
  { 0x34000000, 11 , NDPI_SERVICE_AMAZON /* 52.0.0.0/11        */  },
  { 0x34200000, 13 , NDPI_SERVICE_AMAZON /* 52.32.0.0/13       */  },
  { 0x34280000, 14 , NDPI_SERVICE_AMAZON /* 52.40.0.0/14       */  },
  { 0x342C0000, 15 , NDPI_SERVICE_AMAZON /* 52.44.0.0/15       */  },
  { 0x342E0000, 18 , NDPI_SERVICE_AMAZON /* 52.46.0.0/18       */  },
  { 0x342E5000, 21 , NDPI_SERVICE_AMAZON /* 52.46.80.0/21      */  },
  { 0x342F0000, 16 , NDPI_SERVICE_AMAZON /* 52.47.0.0/16       */  },
  { 0x34300000, 13 , NDPI_SERVICE_AMAZON /* 52.48.0.0/13       */  },
  { 0x34380000, 14 , NDPI_SERVICE_AMAZON /* 52.56.0.0/14       */  },
  { 0x343C0000, 16 , NDPI_SERVICE_AMAZON /* 52.60.0.0/16       */  },
  { 0x343E0000, 15 , NDPI_SERVICE_AMAZON /* 52.62.0.0/15       */  },
  { 0x34400000, 13 , NDPI_SERVICE_AMAZON /* 52.64.0.0/13       */  },
  { 0x34480000, 15 , NDPI_SERVICE_AMAZON /* 52.72.0.0/15       */  },
  { 0x344C0000, 16 , NDPI_SERVICE_AMAZON /* 52.76.0.0/16       */  },
  { 0x344E0000, 15 , NDPI_SERVICE_AMAZON /* 52.78.0.0/15       */  },
  { 0x34500000, 14 , NDPI_SERVICE_AMAZON /* 52.80.0.0/14       */  },
  { 0x34580000, 13 , NDPI_SERVICE_AMAZON /* 52.88.0.0/13       */  },
  { 0x345A0000, 15 , NDPI_SERVICE_AMAZON /* 52.90.0.0/15       */  },
  { 0x345F0000, 21 , NDPI_SERVICE_AMAZON /* 52.95.0.0/21       */  },
  { 0x345F0A00, 23 , NDPI_SERVICE_AMAZON /* 52.95.10.0/23      */  },
  { 0x345F0C00, 22 , NDPI_SERVICE_AMAZON /* 52.95.12.0/22      */  },
  { 0x345F1000, 21 , NDPI_SERVICE_AMAZON /* 52.95.16.0/21      */  },
  { 0x345F1800, 22 , NDPI_SERVICE_AMAZON /* 52.95.24.0/22      */  },
  { 0x345F1E00, 23 , NDPI_SERVICE_AMAZON /* 52.95.30.0/23      */  },
  { 0x345F2200, 23 , NDPI_SERVICE_AMAZON /* 52.95.34.0/23      */  },
  { 0x345F2400, 22 , NDPI_SERVICE_AMAZON /* 52.95.36.0/22      */  },
  { 0x345F3000, 21 , NDPI_SERVICE_AMAZON /* 52.95.48.0/21      */  },
  { 0x345F3800, 22 , NDPI_SERVICE_AMAZON /* 52.95.56.0/22      */  },
  { 0x345F4000, 19 , NDPI_SERVICE_AMAZON /* 52.95.64.0/19      */  },
  { 0x345F6000, 21 , NDPI_SERVICE_AMAZON /* 52.95.96.0/21      */  },
  { 0x345F6800, 22 , NDPI_SERVICE_AMAZON /* 52.95.104.0/22     */  },
  { 0x345F6F00, 24 , NDPI_SERVICE_AMAZON /* 52.95.111.0/24     */  },
  { 0x345F8000, 18 , NDPI_SERVICE_AMAZON /* 52.95.128.0/18     */  },
  { 0x345FC000, 20 , NDPI_SERVICE_AMAZON /* 52.95.192.0/20     */  },
  { 0x345FD400, 22 , NDPI_SERVICE_AMAZON /* 52.95.212.0/22     */  },
  { 0x345FE000, 24 , NDPI_SERVICE_AMAZON /* 52.95.224.0/24     */  },
  { 0x345FF000, 21 , NDPI_SERVICE_AMAZON /* 52.95.240.0/21     */  },
  { 0x345FF800, 22 , NDPI_SERVICE_AMAZON /* 52.95.248.0/22     */  },
  { 0x345FFC00, 23 , NDPI_SERVICE_AMAZON /* 52.95.252.0/23     */  },
  { 0x345FFE00, 24 , NDPI_SERVICE_AMAZON /* 52.95.254.0/24     */  },
  { 0x34778000, 17 , NDPI_SERVICE_AMAZON /* 52.119.128.0/17    */  },
  { 0x347C8000, 17 , NDPI_SERVICE_AMAZON /* 52.124.128.0/17    */  },
  { 0x34818000, 17 , NDPI_SERVICE_AMAZON /* 52.129.128.0/17    */  },
  { 0x34908000, 17 , NDPI_SERVICE_AMAZON /* 52.144.128.0/17    */  },
  { 0x34C00000, 15 , NDPI_SERVICE_AMAZON /* 52.192.0.0/15      */  },
  { 0x34C40000, 14 , NDPI_SERVICE_AMAZON /* 52.196.0.0/14      */  },
  { 0x34C80000, 13 , NDPI_SERVICE_AMAZON /* 52.200.0.0/13      */  },
  { 0x34D00000, 13 , NDPI_SERVICE_AMAZON /* 52.208.0.0/13      */  },
  { 0x34D80000, 14 , NDPI_SERVICE_AMAZON /* 52.216.0.0/14      */  },
  { 0x34DC0000, 15 , NDPI_SERVICE_AMAZON /* 52.220.0.0/15      */  },
  { 0x34DE0000, 16 , NDPI_SERVICE_AMAZON /* 52.222.0.0/16      */  },
  { 0x36400000, 15 , NDPI_SERVICE_AMAZON /* 54.64.0.0/15       */  },
  { 0x36420000, 16 , NDPI_SERVICE_AMAZON /* 54.66.0.0/16       */  },
  { 0x36430000, 17 , NDPI_SERVICE_AMAZON /* 54.67.0.0/17       */  },
  { 0x36440000, 14 , NDPI_SERVICE_AMAZON /* 54.68.0.0/14       */  },
  { 0x36480000, 13 , NDPI_SERVICE_AMAZON /* 54.72.0.0/13       */  },
  { 0x36500000, 12 , NDPI_SERVICE_AMAZON /* 54.80.0.0/12       */  },
  { 0x36900000, 12 , NDPI_SERVICE_AMAZON /* 54.144.0.0/12      */  },
  { 0x36A00000, 12 , NDPI_SERVICE_AMAZON /* 54.160.0.0/12      */  },
  { 0x36B00000, 14 , NDPI_SERVICE_AMAZON /* 54.176.0.0/14      */  },
  { 0x36B60000, 21 , NDPI_SERVICE_AMAZON /* 54.182.0.0/21      */  },
  { 0x36B60800, 22 , NDPI_SERVICE_AMAZON /* 54.182.8.0/22      */  },
  { 0x36B61000, 22 , NDPI_SERVICE_AMAZON /* 54.182.16.0/22     */  },
  { 0x36B68000, 19 , NDPI_SERVICE_AMAZON /* 54.182.128.0/19    */  },
  { 0x36B6A200, 23 , NDPI_SERVICE_AMAZON /* 54.182.162.0/23    */  },
  { 0x36B6A400, 22 , NDPI_SERVICE_AMAZON /* 54.182.164.0/22    */  },
  { 0x36B6A800, 23 , NDPI_SERVICE_AMAZON /* 54.182.168.0/23    */  },
  { 0x36B6AA00, 24 , NDPI_SERVICE_AMAZON /* 54.182.170.0/24    */  },
  { 0x36B6AE00, 23 , NDPI_SERVICE_AMAZON /* 54.182.174.0/23    */  },
  { 0x36B6B000, 21 , NDPI_SERVICE_AMAZON /* 54.182.176.0/21    */  },
  { 0x36B6B800, 22 , NDPI_SERVICE_AMAZON /* 54.182.184.0/22    */  },
  { 0x36B6BF00, 24 , NDPI_SERVICE_AMAZON /* 54.182.191.0/24    */  },
  { 0x36B6C000, 20 , NDPI_SERVICE_AMAZON /* 54.182.192.0/20    */  },
  { 0x36B6D100, 24 , NDPI_SERVICE_AMAZON /* 54.182.209.0/24    */  },
  { 0x36B6D200, 23 , NDPI_SERVICE_AMAZON /* 54.182.210.0/23    */  },
  { 0x36B6D400, 22 , NDPI_SERVICE_AMAZON /* 54.182.212.0/22    */  },
  { 0x36B6D800, 21 , NDPI_SERVICE_AMAZON /* 54.182.216.0/21    */  },
  { 0x36B6E000, 19 , NDPI_SERVICE_AMAZON /* 54.182.224.0/19    */  },
  { 0x36B70000, 16 , NDPI_SERVICE_AMAZON /* 54.183.0.0/16      */  },
  { 0x36B80000, 13 , NDPI_SERVICE_AMAZON /* 54.184.0.0/13      */  },
  { 0x36C00000, 12 , NDPI_SERVICE_AMAZON /* 54.192.0.0/12      */  },
  { 0x36D00000, 13 , NDPI_SERVICE_AMAZON /* 54.208.0.0/13      */  },
  { 0x36D80000, 14 , NDPI_SERVICE_AMAZON /* 54.216.0.0/14      */  },
  { 0x36DC0000, 15 , NDPI_SERVICE_AMAZON /* 54.220.0.0/15      */  },
  { 0x36DF2000, 19 , NDPI_SERVICE_AMAZON /* 54.223.32.0/19     */  },
  { 0x36DF4000, 18 , NDPI_SERVICE_AMAZON /* 54.223.64.0/18     */  },
  { 0x36E00000, 11 , NDPI_SERVICE_AMAZON /* 54.224.0.0/11      */  },
  { 0x3F5C0C00, 22 , NDPI_SERVICE_AMAZON /* 63.92.12.0/22      */  },
  { 0x3FEE0C00, 22 , NDPI_SERVICE_AMAZON /* 63.238.12.0/22     */  },
  { 0x3FEE1000, 23 , NDPI_SERVICE_AMAZON /* 63.238.16.0/23     */  },
  { 0x42074000, 19 , NDPI_SERVICE_AMAZON /* 66.7.64.0/19       */  },
  { 0x43CA0000, 18 , NDPI_SERVICE_AMAZON /* 67.202.0.0/18      */  },
  { 0x4815C000, 19 , NDPI_SERVICE_AMAZON /* 72.21.192.0/19     */  },
  { 0x482C2000, 19 , NDPI_SERVICE_AMAZON /* 72.44.32.0/19      */  },
  { 0x4B658000, 17 , NDPI_SERVICE_AMAZON /* 75.101.128.0/17    */  },
  { 0x4F7D0000, 17 , NDPI_SERVICE_AMAZON /* 79.125.0.0/17      */  },
  { 0x57EE5000, 21 , NDPI_SERVICE_AMAZON /* 87.238.80.0/21     */  },
  { 0x607F0000, 17 , NDPI_SERVICE_AMAZON /* 96.127.0.0/17      */  },
  { 0x67040800, 21 , NDPI_SERVICE_AMAZON /* 103.4.8.0/21       */  },
  { 0x6708AC00, 22 , NDPI_SERVICE_AMAZON /* 103.8.172.0/22     */  },
  { 0x67F69400, 22 , NDPI_SERVICE_AMAZON /* 103.246.148.0/22   */  },
  { 0x6B140000, 14 , NDPI_SERVICE_AMAZON /* 107.20.0.0/14      */  },
  { 0x7AF8C000, 18 , NDPI_SERVICE_AMAZON /* 122.248.192.0/18   */  },
  { 0xAC606000, 20 , NDPI_SERVICE_AMAZON /* 172.96.96.0/20     */  },
  { 0xAE810000, 16 , NDPI_SERVICE_AMAZON /* 174.129.0.0/16     */  },
  { 0xAF298000, 17 , NDPI_SERVICE_AMAZON /* 175.41.128.0/17    */  },
  { 0xB0204000, 19 , NDPI_SERVICE_AMAZON /* 176.32.64.0/19     */  },
  { 0xB0206000, 20 , NDPI_SERVICE_AMAZON /* 176.32.96.0/20     */  },
  { 0xB0207000, 21 , NDPI_SERVICE_AMAZON /* 176.32.112.0/21    */  },
  { 0xB0207800, 22 , NDPI_SERVICE_AMAZON /* 176.32.120.0/22    */  },
  { 0xB0207E00, 23 , NDPI_SERVICE_AMAZON /* 176.32.126.0/23    */  },
  { 0xB0220000, 16 , NDPI_SERVICE_AMAZON /* 176.34.0.0/16      */  },
  { 0xB1478000, 17 , NDPI_SERVICE_AMAZON /* 177.71.128.0/17    */  },
  { 0xB148F000, 21 , NDPI_SERVICE_AMAZON /* 177.72.240.0/21    */  },
  { 0xB2EC0000, 20 , NDPI_SERVICE_AMAZON /* 178.236.0.0/20     */  },
  { 0xB8480000, 15 , NDPI_SERVICE_AMAZON /* 184.72.0.0/15      */  },
  { 0xB8A98000, 17 , NDPI_SERVICE_AMAZON /* 184.169.128.0/17   */  },
  { 0xB9307800, 22 , NDPI_SERVICE_AMAZON /* 185.48.120.0/22    */  },
  { 0xB98F1000, 22 , NDPI_SERVICE_AMAZON /* 185.143.16.0/22    */  },
  { 0xC77FE800, 22 , NDPI_SERVICE_AMAZON /* 199.127.232.0/22   */  },
  { 0xC7FFC000, 22 , NDPI_SERVICE_AMAZON /* 199.255.192.0/22   */  },
  { 0xCB53DC00, 22 , NDPI_SERVICE_AMAZON /* 203.83.220.0/22    */  },
  { 0xCCEC8000, 17 , NDPI_SERVICE_AMAZON /* 204.236.128.0/17   */  },
  { 0xCCF6A000, 19 , NDPI_SERVICE_AMAZON /* 204.246.160.0/19   */  },
  { 0xCDFBC000, 18 , NDPI_SERVICE_AMAZON /* 205.251.192.0/18   */  },
  { 0xCFABA000, 19 , NDPI_SERVICE_AMAZON /* 207.171.160.0/19   */  },
  { 0xD02FF800, 23 , NDPI_SERVICE_AMAZON /* 208.47.248.0/23    */  },
  { 0xD1C96000, 22 , NDPI_SERVICE_AMAZON /* 209.201.96.0/22    */  },
  { 0xD8892000, 19 , NDPI_SERVICE_AMAZON /* 216.137.32.0/19    */  },
  { 0xD8B6E000, 20 , NDPI_SERVICE_AMAZON /* 216.182.224.0/20   */  },
  /*
    Telegram Messenger LLP
    origin: AS62041, AS62014, AS59930
   */
  { 0x5B6C0400, 22 , NDPI_PROTOCOL_TELEGRAM /* 91.108.4.0/22      */  },
  { 0x5B6C0800, 21 , NDPI_PROTOCOL_TELEGRAM /* 91.108.8.0/21      */  },
  { 0x5B6C1000, 21 , NDPI_PROTOCOL_TELEGRAM /* 91.108.16.0/21     */  },
  { 0x5B6C3800, 22 , NDPI_PROTOCOL_TELEGRAM /* 91.108.56.0/22     */  },
  { 0x959AA000, 20 , NDPI_PROTOCOL_TELEGRAM /* 149.154.160.0/20   */  },
  /*
    Twitch Interactive Inc.
    origin AS46489
   */
  { 0x17A00000, 24 , NDPI_SERVICE_TWITCH /* 23.160.0.0/24      */  },
  { 0x2D718000, 22 , NDPI_SERVICE_TWITCH /* 45.113.128.0/22    */  },
  { 0x34DFC000, 18 , NDPI_SERVICE_TWITCH /* 52.223.192.0/18    */  },
  { 0x67353000, 22 , NDPI_SERVICE_TWITCH /* 103.53.48.0/22     */  },
  { 0xB92ACC00, 22 , NDPI_SERVICE_TWITCH /* 185.42.204.0/22    */  },
  { 0xC0104000, 21 , NDPI_SERVICE_TWITCH /* 192.16.64.0/21     */  },
  { 0xC06CEF00, 24 , NDPI_SERVICE_TWITCH /* 192.108.239.0/24   */  },
  { 0xC709F800, 21 , NDPI_SERVICE_TWITCH /* 199.9.248.0/21     */  },
  /*
    Blizzard Entertainment, Inc
    origin AS57976
   */
  { 0x052AA000, 19 , NDPI_PROTOCOL_STARCRAFT /* 5.42.160.0/19      */  },
  { 0x0C81DE00, 23 , NDPI_PROTOCOL_STARCRAFT /* 12.129.222.0/23    */  },
  { 0x0C81E400, 23 , NDPI_PROTOCOL_STARCRAFT /* 12.129.228.0/23    */  },
  { 0x0C81EC00, 23 , NDPI_PROTOCOL_STARCRAFT /* 12.129.236.0/23    */  },
  { 0x0C81FE00, 23 , NDPI_PROTOCOL_STARCRAFT /* 12.129.254.0/23    */  },
  { 0x0C82F400, 22 , NDPI_PROTOCOL_STARCRAFT /* 12.130.244.0/22    */  },
  { 0x18690000, 18 , NDPI_PROTOCOL_STARCRAFT /* 24.105.0.0/18      */  },
  { 0x25F40000, 18 , NDPI_PROTOCOL_STARCRAFT /* 37.244.0.0/18      */  },
  { 0x3B992800, 22 , NDPI_PROTOCOL_STARCRAFT /* 59.153.40.0/22     */  },
  { 0x3E73F400, 22 , NDPI_PROTOCOL_STARCRAFT /* 62.115.244.0/22    */  },
  { 0x50EFD000, 22 , NDPI_PROTOCOL_STARCRAFT /* 80.239.208.0/22    */  },
  { 0x67047200, 23 , NDPI_PROTOCOL_STARCRAFT /* 103.4.114.0/23     */  },
  { 0x67C62000, 23 , NDPI_PROTOCOL_STARCRAFT /* 103.198.32.0/23    */  },
  { 0x89DD4000, 18 , NDPI_PROTOCOL_STARCRAFT /* 137.221.64.0/18    */  },
  { 0xB93C7000, 22 , NDPI_PROTOCOL_STARCRAFT /* 185.60.112.0/22    */  },
  { 0xC30CF400, 22 , NDPI_PROTOCOL_STARCRAFT /* 195.12.244.0/22    */  },
  { 0xC76C2000, 19 , NDPI_PROTOCOL_STARCRAFT /* 199.108.32.0/19    */  },
  { 0xCA094200, 23 , NDPI_PROTOCOL_STARCRAFT /* 202.9.66.0/23      */  },
  /*
    AnchorFree, Inc. (Hotspot Shield)
    origin AS26642
   */
  { 0x2E102200, 23 , NDPI_SERVICE_HOTSPOT_SHIELD /* 46.16.34.0/23      */  },
  { 0x32752D00, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 50.117.45.0/24     */  },
  { 0x3F8DC600, 23 , NDPI_SERVICE_HOTSPOT_SHIELD /* 63.141.198.0/23    */  },
  { 0x4A730100, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 74.115.1.0/24      */  },
  { 0x4A730500, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 74.115.5.0/24      */  },
  { 0x4A730600, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 74.115.6.0/24      */  },
  { 0x55EDC500, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 85.237.197.0/24    */  },
  { 0x55EDDE00, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 85.237.222.0/24    */  },
  { 0xC62F7300, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 198.47.115.0/24    */  },
  { 0xC6906800, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 198.144.104.0/24   */  },
  { 0xC7FFD700, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 199.255.215.0/24   */  },
  { 0xCC0E4A00, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 204.14.74.0/24     */  },
  { 0xCC0E4C00, 23 , NDPI_SERVICE_HOTSPOT_SHIELD /* 204.14.76.0/23     */  },
  { 0xCC0E4E00, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 204.14.78.0/24     */  },
  { 0xCDA42000, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 205.164.32.0/24    */  },
  { 0xD1498400, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 209.73.132.0/24    */  },
  { 0xD1499700, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 209.73.151.0/24    */  },
  { 0xD8AC8E00, 24 , NDPI_SERVICE_HOTSPOT_SHIELD /* 216.172.142.0/24   */  },
  { 0x0, 0, 0 }
};