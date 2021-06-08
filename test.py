# ActiveSync diagnostics script
# Author: Mukunda Johnson (mukunda@mukunda.com)
#
# This implements a small portion of the ActiveSync protocol for diagnostic purposes and
#  may be a useful example for other developers tasked with similar hellish quests.
#
# Please note this script is not designed to be reusable. A lot of things are hardcoded
#  for my specific case.
#/////////////////////////////////////////////////////////////////////////////////////////
import requests, urllib3, base64, struct, clipboard, os
import code, json, random, re, string, time
import xml.etree.ElementTree as ET
from email import utils
from datetime import datetime
#/////////////////////////////////////////////////////////////////////////////////////////

import logging
# These two lines enable debugging at httplib level (requests->urllib3->http.client)
# You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# The only thing missing will be the response.body which is not logged.
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1

# You must initialize logging, otherwise you'll not see debug output.
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


# We want to avoid any SSL warnings and such.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#-----------------------------------------------------------------------------------------
user_agent = "MJOHNSON-TEST/1.0" # User agent to use.

#-----------------------------------------------------------------------------------------
# A lot of the data we want to be persistent across script executions. These help with
#  saving/sharing data.
def get_data( name ):
   if not os.path.exists( "data-" + name ): return 0
   with open( "data-" + name, "rb" ) as f:
      return json.load(f)

def get_key( name ):
   if not os.path.exists( "key-" + name ): return 0
   with open( "key-" + name, "r" ) as f:
      return int( f.read().strip() )

#-----------------------------------------------------------------------------------------
def set_data( name, data ):
   with open( "data-" + name, "w", encoding="utf-8" ) as f: json.dump( data, f, indent=3 )

def set_key( name, value ):
   with open( "key-" + name, "w" ) as f: f.write( str(value) )

#-----------------------------------------------------------------------------------------
# Build an ActiveSync command string, appended to requests as a query param
def getcmd( command, params={}, policy_key=get_key("policy") ):
   account = get_data( "account" )

   device_type = b"SP" # smartphone
   protocol_version = 141
   locale = 0x0409 # Locale code: en-US, see MS-LCID.pdf
   de = account["device"].encode("utf-8")

   # List of activesync commands
   commands = {
      "sync": 0,
      "sendmail": 1,
      "smartforward": 2,
      "smartreply": 3,
      "getattachment": 4,
      "foldersync": 9,
      "foldercreate": 10,
      "folderdelete": 11,
      "folderupdate": 12,
      "moveitems": 13,
      "getitemestimate": 14,
      "meetingresponse": 15,
      "search": 16,
      "settings": 17,
      "ping": 18,
      "itemoperations": 19,
      "provision": 20,
      "resolverecipients": 21,
      "validatecert": 22,
   }

   # Tags that can be attached, but we aren't using these.
   tags = {
      "attachmentname": 0,
      "collectionid": 1,
      "itemid": 3,
      "longid": 4,
      "occurrence": 6,
      "options": 7,
      "user": 8,
   }

   print( "--" )
   print( "Building command:", command )
   print( "Params:", params )

   # https://docs.microsoft.com/en-us/previous-versions/office/developer/exchange-server-interoperability-guidance/hh361570(v=exchg.140)
   # their class adds a user
   #params['user'] = "tbox"account['username']
   #print("POLICYKEY", policy_key)
   header = struct.pack(
      f"<BBHB{len(de)}sBIB{len(device_type)}s",
      protocol_version, commands[command.lower()], locale,
      len(de), de,
      4, int(policy_key),
      len(device_type), device_type
   )

   encoded_params = b''
   for k, v in params.items():
      v = str(v).encode("utf-8")
      encoded_params += struct.pack( "BB", tags[k.lower()], len(v) ) + v

   return base64.b64encode(header + encoded_params).decode("ascii")

#-----------------------------------------------------------------------------------------
# Set the account and server to be used for tests. This is used first.
def set_account( server, username, password, endpoint="Microsoft-Server-ActiveSync", https=False, deviceid=None ):
   print( "OK, setting account data.")

   print( "- Deleting previous data files." )
   os.system( "del *.tmp" )
   os.system( "del data-*" )
   os.system( "del key-*")
   
   if deviceid == None:
      print( "- Generating device ID.")
      deviceid = "testdevice" + "".join(random.choices(string.digits,k=6))
   print( f"- deviceid = {deviceid}")

   set_data( "account", {
      "server": server,
      "username": username,
      "password": password,
      "device": deviceid,
      "endpoint": endpoint,
      "https": https,
   })

#-----------------------------------------------------------------------------------------
def get_service_url():
   account = get_data( "account" )
   protocol = "https" if account["https"] else "http"
   return f"{protocol}://{account['server']}/{account['endpoint']}"



#-----------------------------------------------------------------------------------------
# Get our general request headers including the basic auth.
def get_request_headers():
   creds = get_data( "account" )
   auth = base64.b64encode( f"{creds['username']}:{creds['password']}".encode("ascii") ).decode("ascii")

   return {
      "User-Agent": user_agent,
      "Authorization": f"Basic {auth}",
      "Content-Type": "application/vnd.ms-sync.wbxml"
   }

#-----------------------------------------------------------------------------------------
# Test getting OPTIONS from the server.
# This will also overwrite the current account credentials (will mess up provisioning if
#  you use a different account).
def get_options():
   account = get_data( "account" )

   headers = get_request_headers().copy()
   headers["MS-ASProtocolVersion"] = "14.1"
   return requests.options( f"{get_service_url()}", verify=False, headers=headers, params={
      "User": account["username"],
      "DeviceId": account["device"],
      "DeviceType": "SP"
   })

#-----------------------------------------------------------------------------------------
# Converts XML to WBXML for ActiveSync
# Don't need to specify headers for XML, just the payload
# Returns bytes
def make_body( content ):
   inpath = "wbxml-xml-input.tmp"
   outpath = "wbxml-xml-converted.tmp"
   if os.path.exists( outpath ):
      os.remove( outpath )
   with open( inpath, "w", encoding="utf-8" ) as f:
      # Prepend XML version and ActiveSync language.
      f.write( '''<?xml version="1.0"?>
<!DOCTYPE ActiveSync PUBLIC "-//MICROSOFT//DTD ActiveSync//EN" "http://www.microsoft.com/">'''
      + content.strip() )

   os.system( f"libwbxml\\xml2wbxml.exe -a -n -v 1.3 -o {outpath} {inpath}" )
   with open( outpath, "rb" ) as f:
      return f.read()

#   return wbxml.xml_to_wbxml('''<?xml version="1.0"?>
#<!DOCTYPE ActiveSync PUBLIC "-//MICROSOFT//DTD ActiveSync//EN" "http://www.microsoft.com/">''' + content.strip() )

#-----------------------------------------------------------------------------------------
# Converts WBXML to XML with ActiveSync schema.
def convert_wbxml( content ):
   print( "converting wbxml content..." )
   if os.path.exists( "wbxml-output.tmp" ):
      os.remove( "wbxml-output.tmp" )

   with open("wbxml-input.tmp","wb") as f:
      f.write( content )

   os.system( "libwbxml\\wbxml2xml.exe -l ACTIVESYNC -m 1 -c UTF-8 -o wbxml-output.tmp wbxml-input.tmp")
   with open("wbxml-output.tmp", "r", encoding="utf-8") as f:
      return f.read()

#***********************************************************************************
# I believe that the trailing colons found in the xmlns may be a bug in libwbxml. It
#  doesn't recognize the code pages without that and breaks encoding and decoding.
#***********************************************************************************

#-----------------------------------------------------------------------------------------
# Test function to provision a new device. Must be done before other tests.
# This will cache the username and password for authentication for other requests.
def provision_device():
   
   cmd = getcmd( "provision", policy_key=0 )

   print( "Requesting policy..." )
   # A lot of this stuff is just copied from wireshark inspections, mainly the WindowsMail
   #  handshake. Hardcoding some common stuff (though note a real android/iphone wouldn't
   #  report Windows OS)

   # body = make_body(f'''
   # <Provision xmlns="Provision:" xmlns:settings="Settings:">
   #    <settings:DeviceInformation>
   #       <settings:Set>
   #          <settings:Model>MJohnson Test</settings:Model>
   #          <settings:IMEI />
   #          <settings:FriendlyName>MJOHNSONTEST</settings:FriendlyName>
   #          <settings:OS>Windows 10.0.19041</settings:OS>
   #          <settings:OSLanguage>English</settings:OSLanguage>
   #          <settings:PhoneNumber />
   #          <settings:MobileOperator>OperatorName</settings:MobileOperator>
   #          <settings:EnableOutboundSMS>0</settings:EnableOutboundSMS>
   #          <settings:UserAgent>{user_agent}</settings:UserAgent>
   #       </settings:Set>
   #    </settings:DeviceInformation>
   #    <Policies>
   #       <Policy>
   #          <PolicyType>MS-EAS-Provisioning-WBXML</PolicyType>
   #       </Policy>
   #    </Policies>
   # </Provision>''')

   #sesh = requests.session()
   #sesh.headers = { "Accept-Encoding": "*" }

   # creds = get_data( "account" )
   # auth = base64.b64encode( f"{creds['username']}:{creds['password']}".encode("ascii") ).decode("ascii")
   # print( get_service_url() )
   # a = sesh.options( f"{get_service_url()}/?User=tbox&DeviceId=testdevice9298129441744935&DeviceType=SP", verify=False, headers={
      
   #    "User-Agent": user_agent,
   #    "Authorization": f"Basic {auth}",
   #    "MS-ASProtocolVersion": "2.5"
   # })
   
   #print( a.status_code )
   #print( a.headers )
   
   body = make_body(f'''
   <Provision xmlns="Provision:" xmlns:settings="Settings:">
      <settings:DeviceInformation>
         <settings:Set>
            <settings:Model>MJohnson Test</settings:Model>
            <settings:IMEI />
            <settings:FriendlyName>MJOHNSONTEST</settings:FriendlyName>
            <settings:OS>Test OS 1.0</settings:OS>
            <settings:OSLanguage>English</settings:OSLanguage>
            <settings:PhoneNumber />
            <settings:UserAgent>{user_agent}</settings:UserAgent>
            <settings:EnableOutboundSMS>0</settings:EnableOutboundSMS>
            <settings:MobileOperator>OperatorName</settings:MobileOperator>
         </settings:Set>
      </settings:DeviceInformation>
      <Policies>
         <Policy>
            <PolicyType>MS-EAS-Provisioning-WBXML</PolicyType>
         </Policy>
      </Policies>
   </Provision>''')
   #return;
   #print('---')
   #print(body)
   #print('---')

   #print( f"{get_service_url()}?{cmd}", body, get_request_headers(),False )
   a = requests.post( f"{get_service_url()}?{cmd}", data=body, headers=get_request_headers(),verify=False )
   print( "Got", a.status_code, "response" )
   if( a.status_code != 200 ):
      print( "-- Printing non 200 response and quitting --" )
      print( a.content )
      return
   xml = convert_wbxml( a.content )
   print( xml )
   xml = ET.fromstring(xml)
   
   policy_key = (xml.find("{Provision:}Policies")
                    .find("{Provision:}Policy")
                    .find("{Provision:}PolicyKey")).text

   set_key( "policy", policy_key )

   # ASPROV 4.1.3
   print( "Confirming policy" )
   body = make_body(f'''
      <Provision xmlns="Provision:">
         <Policies>
            <Policy>
               <PolicyType>MS-EAS-Provisioning-WBXML</PolicyType>
               <PolicyKey>{get_key('policy')}</PolicyKey>
               <Status>1</Status>
            </Policy>
         </Policies>
      </Provision>''')
   # We will also use this policy key in other commands.

   cmd = getcmd( "provision" )
   a = requests.post( f"{get_service_url()}?{cmd}", data=body, headers=get_request_headers(),verify=False )
   print( "Got", a.status_code, "response" )
   xml = convert_wbxml( a.content )
   print( xml )
   xml = ET.fromstring(xml)

   # use the second policy key.
   policy_key = (xml.find("{Provision:}Policies")
                    .find("{Provision:}Policy")
                    .find("{Provision:}PolicyKey")).text

   set_key( "policy", policy_key )

   # Note that Windows Mail also sends a Settings command here. It contains much the same
   #  data as the initial provision request.

#-----------------------------------------------------------------------------------------
def print_options():
   a = get_options()

   print( "--" )
   print( "Options response headers:" )
   print( a.headers )

#-----------------------------------------------------------------------------------------
# Request a list of folders and save the result. This must be used before syncing.
def folder_sync():

   cmd = getcmd( "foldersync" )
   print( "Folder sync..." )
   body = make_body('''
      <FolderSync xmlns="FolderHierarchy:">
         <SyncKey>0</SyncKey>
      </FolderSync>
   ''')
   
   a = requests.post( f"{get_service_url()}?{cmd}", data=body, headers=get_request_headers(), verify=False )
   print( "Got", a.status_code, "response" )
   xml = convert_wbxml( a.content )
   print( xml )
   xml = ET.fromstring(xml)

   sync_key = (xml.find("{FolderHierarchy:}SyncKey")).text
   set_key( "foldersync", sync_key )

   try:
      print( "Decoding sync key:", base64.b64decode(sync_key.encode('ascii')) )
   except:
      print( "sync key =", sync_key )

   # All folders will be "additions" to the empty state.
   folders = []
   for child in xml.find("{FolderHierarchy:}Changes").findall("{FolderHierarchy:}Add"):
      folders.append({
         "server_id": child.find( "{FolderHierarchy:}ServerId").text,
         "parent_id": child.find( "{FolderHierarchy:}ParentId").text,
         "display_name": child.find( "{FolderHierarchy:}DisplayName").text,
         "type": child.find( "{FolderHierarchy:}Type").text
      })

   set_data( "folders", folders )

#-----------------------------------------------------------------------------------------
# Get the folder ID of a folder name.
def get_folder_id( name ):
   folders = get_data( "folders" )
   for folder in folders:
      if folder["display_name"].lower() == name.lower():
         return folder["server_id"]
   return None

#-----------------------------------------------------------------------------------------
# Test a "ping" command on the specified folder. Will not return until the ping finishes.
# Ping command is the push notification wait.
def test_ping( folder="Inbox" ):
   folder_id = get_folder_id( "Inbox" )
   cmd = getcmd( "ping" )
   print( "Pinging..." )
   body = make_body(f'''
      <Ping xmlns="Ping:">
         <HeartbeatInterval>60</HeartbeatInterval>
         <Folders>
            <Folder>
               <Id>{folder_id}</Id>
               <Class>Email</Class>
            </Folder>
         </Folders>
      </Ping>
   ''')

   a = requests.post( f"{get_service_url()}?{cmd}", data=body, headers=get_request_headers(), verify=False )
   print( "Got", a.status_code, "response" )
   xml = convert_wbxml( a.content )
   print( xml )

#-----------------------------------------------------------------------------------------
# Initialize sync for a folder. This must be done before testing further sync commands. It
#  fetches the first sync key by sending a sync key of "0".
def test_sync_reset( folder="Inbox" ):
   folder_id = get_folder_id( folder )
   
   # Starting fetch with synckey 0
   # <BodyPreference> is defined in MS-ASAIRS
   #  4 = MIME
   # <Conflict> is an optional key you may see in wireshark, but it defaults to 1 (server wins)
   # <FilterType> option controls sync period, 0 = sync all items
   # <MimeSupport> is defined in MS-ASCMD 2.2.3.100.3
   # 1: Send MIME data for S/MIME messages only. Send regular body for all other messages.
   #  Not really sure what this does.
   cmd = getcmd( "sync" )
   print( "Folder sync..." )
   body = make_body(f'''
      <Sync xmlns="AirSync:">
         <Collections>
            <Collection>
               <SyncKey>0</SyncKey>
               <CollectionId>{folder_id}</CollectionId>
               <Options>
                  <BodyPreference xmlns="AirSyncBase:">
                     <Type>4</Type>
                  </BodyPreference>
                  <MIMESupport>1</MIMESupport>
               </Options>
            </Collection>
         </Collections>
      </Sync>
   ''')
   
   a = requests.post( f"{get_service_url()}?{cmd}", data=body, headers=get_request_headers(),verify=False )
   print( "Got", a.status_code, "response" )
   xml = convert_wbxml( a.content )
   print( xml )
   xml = ET.fromstring(xml)

   data = []
   for child in xml.find("{AirSync:}Collections").findall("{AirSync:}Collection"):
      sync_key = child.find("{AirSync:}SyncKey").text
      data.append({
         #"class"         : child.find("{AirSync:}Class").text,
         "sync_key"      : child.find("{AirSync:}SyncKey").text,
         "collection_id" : child.find("{AirSync:}CollectionId").text,
         "status"        : child.find("{AirSync:}Status").text,
      })

      try:
         print( "Decoding sync key:", base64.b64decode(sync_key.encode('ascii')) )
      except:
         print( "sync key:", sync_key )

   set_data( f"sync-{folder.lower()}", data )
   set_data( f"emails-{folder.lower()}", {} )

def get_readable_sync_key( key ):
   try:
      base64.b64decode(key.encode('ascii'))
   except:
      return key

#-----------------------------------------------------------------------------------------
# Test the sync command
# update_synckey=False means to discard the sync key, so we can test packet loss by
#  sending the same sync key again and again
# kill_emails=True would mean to throw away the email data so we don't overload ourselves
#  during stress tests.
# setread={serverID} is used to issue a <Change> command and set the read flag for the
#  specified email via its server ID.
def test_sync( folder="Inbox", update_synckey=True, kill_emails=False, setread=None ):
   syncdata = get_data( f"sync-{folder.lower()}" )
   # Use entry 0
   
   print( "Current sync key:", get_readable_sync_key(syncdata[0]["sync_key"]) )

   # Test if making changes while syncing can cause breakage.
   if setread != None:
      setread = f'''
      <Commands>
         <Change>
            <ServerId>{setread}</ServerId>
            <ApplicationData>
               <Read xmlns="Email:">1</Read>
            </ApplicationData>
         </Change>
      </Commands>
      '''
   else:
      setread = ""

   cmd = getcmd( "sync" )
   print( "Folder sync 2..." )
   body = make_body(f'''
      <Sync xmlns="AirSync:">
         <Collections>
            <Collection>
               <SyncKey>{syncdata[0]["sync_key"]}</SyncKey>
               <CollectionId>{syncdata[0]["collection_id"]}</CollectionId>
               <Options>
                  <BodyPreference xmlns="AirSyncBase:">
                     <Type>4</Type>
                  </BodyPreference>
                  <MIMESupport>1</MIMESupport>
               </Options>
               {setread}
            </Collection>
         </Collections>
      </Sync>
   ''')
   
   a = requests.post( f"{get_service_url()}?{cmd}", data=body, headers=get_request_headers(),verify=False )
   print( "Got", a.status_code, "response" )
   if len(a.content) == 0:
      print( "<Empty response, no new data.>" )
      return
   xml = convert_wbxml( a.content )
   print( xml )
   xml = ET.fromstring(xml)
   
   col = xml.find("{AirSync:}Collections").find("{AirSync:}Collection")

   data = []
   emails = get_data( f"emails-{folder.lower()}" )
   for child in xml.find("{AirSync:}Collections").findall("{AirSync:}Collection"):
      # Try NOT updating sync key
      data.append({
         #"class"         : child.find("{AirSync:}Class").text,
         "sync_key"      : child.find("{AirSync:}SyncKey").text,
         "collection_id" : child.find("{AirSync:}CollectionId").text,
         "status"        : child.find("{AirSync:}Status").text,
      })

      print( "Decoding sync key:", get_readable_sync_key(syncdata[0]["sync_key"]) )

      if child.find("{AirSync:}Commands") == None: continue

      with open( "data-email-log", "a" ) as log:
         for mail in child.find("{AirSync:}Commands").findall("{AirSync:}Add"):
            server_id = mail.find("{AirSync:}ServerId").text
            if not server_id in emails: emails[server_id] = {}

            appdata = mail.find( "{AirSync:}ApplicationData" )

            def copy_field( source ):
               node = appdata.find( "{Email:}" + source )
               if node != None:
                  emails[server_id][source] = node.text

            copy_field( "To" )
            copy_field( "From" )
            copy_field( "Subject" )
            copy_field( "Read" )
            copy_field( "DisplayTo" )
            copy_field( "ThreadTopic" )
            copy_field( "DateReceived" )

            print( "Adding email" )
            print( emails[server_id] )
            
            log.write( emails[server_id]["Subject"] + "\n" )

   if( update_synckey ):
      print( "<updating sync data for next fetch.>")
      set_data( f"sync-{folder.lower()}", data )

   if kill_emails:
      # Test feature for not keeping track of changes where we are only interested in ADD
      #  commands in email_log.txt
      emails = {}

   set_data( f"emails-{folder.lower()}", emails )

#def test_sendmail( mailfrom="tbox@nemesis.local", mailto="tbox@nemesis.local", subject="", body="" ):
   
#-----------------------------------------------------------------------------------------
# Prints all emails that we have received (excluding anytihng we have already discarded).
def print_emails( folder="Inbox" ):
   emails = get_data(f"emails-{folder.lower()}")

   # Merge ID into the entries and convert to a list.
   emails = [y.update({"id":x}) or y for x,y in emails.items()]


   def email_unixtime(email):
      # Convert email time 2021-05-21T15:53:44.000Z to unixtime
      # fromisoformat doesn't support Z
      return datetime.fromisoformat(email["DateReceived"].replace("Z","+00:00")).timestamp()

   emails = sorted( emails, key = email_unixtime )

   for e in emails:
      print( e["id"], e["Subject"] + " / " + e["DateReceived"] )

#-----------------------------------------------------------------------------------------
# The email log simply tracks subjects. This is to test if any expected emails number from
#  1-x are duplicate or missing.
def test_email_log( prefix, limit ):
   data = {}
   with open( "data-email-log", "r" ) as inp:
      for line in inp:
         tokens = line.split()
         if tokens[0] == prefix:
            data[tokens[1]] = data.get( tokens[1], 0 ) + 1

   for i in range( 1, limit+1 ):
      id = str(i)
      if data.get( id, 0 ) == 0:
         print( f"missing ID {id}!" )

   for i in range( 1, limit+1 ):
      id = str(i)
      if data.get( id, 0 ) > 1:
         print( f"ID {id} appears {data[id]} times!" )

#-----------------------------------------------------------------------------------------
# Copy index.fld data to clipboard and run this function to decode the data into readable
#  text.
def pin(): # print index
   text = clipboard.paste().strip()
   first = True
   for t in text.split("\n"):
      t = t.strip().split(" ")
      vals = {}
      for v in t:
         vals[v[0]] = v[1:]

      def convtime( tm ):
         if tm != None:
            return datetime.fromtimestamp( int(tm, base=16) ).strftime( '%Y-%m-%d %H:%M:%S' )
         else:
            return ""
      
      if not first:
         print( "---" )
      else:
         first = False

      print( "UUID:", vals.get("U") )
      print( "Flags:", vals.get("F") )
      print( "Delivered:", vals.get("D"), convtime(vals.get("D")) )
      print( "Created:", vals.get("T"), convtime(vals.get("T")) )
      print( "Modified:", vals.get("M"), convtime(vals.get("M")) )
      print( "Type:", vals.get("C") )

#-----------------------------------------------------------------------------------------
# Copy ActiveSync binary data from the KC debug log and use this function to decode the
#  data into readable xml.
def decode_clip():
   text = clipboard.paste()
   if text.find( "{activesync}" ) != -1:
      print( "Debuglog detected. Cleaning up text." )
      # Clean up input.
      text = "\n".join(re.findall( r"{activesync} \d+: ([0-9a-f]+) \|", text ))

   # Simple cleanup
   text = re.sub( r"[\s]", "", text )
   bs = bytes.fromhex( text )
   xml = convert_wbxml( bs )
   print( xml )
   clipboard.copy( xml )
   print ("<copied to clipboard>")

#-----------------------------------------------------------------------------------------
# Decode base64 text into ascii/utf8.
def decode_b64():
   text = clipboard.paste()
   print( "Input:", text )
   converted = base64.b64decode( text.encode("ascii") )
   print( "Raw:", converted )
   with open( "decode-b64.tmp", "wb" ) as f:
      f.write( converted )
   converted = converted.decode("utf-8")
   print( "Output:", converted )
   clipboard.copy( converted )

def makejunk( length ):
   return "".join(random.choices(string.digits+string.ascii_letters,k=length))

gnow = int(time.time())
#-----------------------------------------------------------------------------------------
def test_sendmail( clientid, subject, body, recipient, date, attachment_size=0, save_in_sent_items=True ):
   account = get_data( "account" )
   date = utils.formatdate(date)

   attachment = ""
   if attachment_size > 0:
      attachment = f'''--main-email-container
Content-Type: text/plain; name="attachment.txt"
Content-Disposition: attachment; filename="attachment.txt"

{makejunk( attachment_size )}
'''

   print( "Creating email..." )
   mime = f'''Date: {date}
From: {account["username"]}
To: {recipient}
Subject: {subject}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="main-email-container"

--main-email-container
Content-Type: multipart/alternative; boundary="email-piece-boundary"

--email-piece-boundary
Content-Type: text/plain; charset="utf-8"

{body}
--email-piece-boundary
Content-Type: text/html; charset="utf-8"

<html><head></head><body>{body}</body></html>
--email-piece-boundary--
{attachment}--main-email-container--
'''

   print( mime )
   print('--')

   #mime = mime.encode("utf-8")
   #mime = base64.b64encode( mime ).decode("ascii")

   #print('b64content')
   #print(mime)
   
   save_in_sent_items = "<SaveInSentItems/>" if save_in_sent_items else ""

   # The MIME field is a huge can of worms. Don't be fooled -- it's not a base64 string.
   # It's passed as an 'opaque object'. The text should be visible in the protocol as 
   # normal plain text.
   print( "Sending email..." )
   body = make_body(f'''
      <SendMail xmlns="ComposeMail:">
         <ClientId>{clientid}</ClientId>
         {save_in_sent_items}
         <MIME><![CDATA[{mime}]]></MIME>
      </SendMail>
   ''')

   # Don't ask me why it ends up as REPLACEWITHBODYTEXTL==

######
   print("THE BODY CONTGENT IS RIGHTHERE")
   print( body )
   xml = convert_wbxml( body )
   print(xml)
   # body = body.replace( b"REPLACEWITHBODYTEXTLOA==", mime )
   # print(body)
   # return
   # print( body )
   # xml = convert_wbxml( body )
   # print(xml)
   
   cmd = getcmd( "sendmail" )
   a = requests.post( f"{get_service_url()}?{cmd}", data=body, headers=get_request_headers(),verify=False )
   print( "Got", a.status_code, "response" )
   if len(a.content) == 0:
      print( "<Empty response.>" )
      return
   xml = convert_wbxml( a.content )
   print( xml )

# Open the python interpreter after our program loads.
code.interact( local=locals() )

#/////////////////////////////////////////////////////////////////////////////////////////