#!/usr/bin/python

####
#
# Meant to help debug repodata generation issues ; this script will query the regeneration of the repodata through api or through an entry in the db.
#
####
__author__ = "Felix Dewaleyne"
__credits__ = ["Felix Dewaleyne"]
__license__ = "GPL"
__version__ = "3.0.0"
__maintainer__ = "Felix Dewaleyne"
__email__ = "fdewaley@redhat.com"
__status__ = "Production"

##
# will work for 5.4 and 5.5
# will work for 5.3 only if using the database options (--db --cleandb)
##

###
# To the extent possible under law, Red Hat, Inc. has dedicated all copyright to this software to the public domain worldwide, pursuant to the CC0 Public Domain Dedication. 
# This software is distributed without any warranty.  See <http://creativecommons.org/publicdomain/zero/1.0/>.
###

import xmlrpclib, sys, getpass, ConfigParser, os, optparse, warnings, stat, re

#global variables
client=None;
SATELLITE_LOGIN=None;
config = ConfigParser.ConfigParser()
config.read(['.satellite', os.path.expanduser('~/.satellite'), '/etc/sysconfig/rhn/satellite'])

# this will initialize a session and return its key.
# for security reason the password is removed from memory before exit, but we want to keep the current username.
def session_init(orgname='baseorg', settings={} ):
    global client;
    global config;
    global SATELLITE_LOGIN;
    if 'url' in settings:
        SATELLITE_URL = settings['url']
    elif config.has_section('default') and config.has_option('default', 'url'):
        SATELLITE_URL = config.get('default','url')
    else:
        sys.stderr.write("enter the satellite url, such as https://satellite.example.com/rpc/api")
        sys.stderr.write("\n")
        SATELLITE_URL = raw_input().strip()
    #format the url if a part is missing
    if re.match('^http(s)?://[\w\-.]+/rpc/api',SATELLITE_URL) == None:
        if re.search('^http(s)?://', SATELLITE_URL) == None:
            SATELLITE_URL = "https://"+SATELLITE_URL
        if re.search('/rpc/api$', SATELLITE_URL) == None:
            SATELLITE_URL = SATELLITE_URL+"/rpc/api"
    if 'login' in settings:
        SATELLITE_LOGIN = settings['login']
    elif config.has_section(orgname) and config.has_option(orgname, 'username'):
        SATELLITE_LOGIN = config.get(orgname, 'username')
    else:
        sys.stderr.write("Login details for %s\n\n" % SATELLITE_URL)
        sys.stderr.write("Login: ")
        SATELLITE_LOGIN = raw_input().strip()
    if 'password' in settings:
        SATELLITE_PASSWORD = settings['password']
    elif config.has_section(orgname) and config.has_option(orgname, 'password'):
        SATELLITE_PASSWORD = config.get(orgname, 'password')
    else:
        SATELLITE_PASSWORD = getpass.getpass(prompt="Password: ")
        sys.stderr.write("\n")
    #inits the connection
    client = xmlrpclib.Server(SATELLITE_URL, verbose=0)
    key = client.auth.login(SATELLITE_LOGIN, SATELLITE_PASSWORD)
    # removes the password from memory
    del SATELLITE_PASSWORD
    return key

def print_channels(key):
    global client;
    print "Channels:"
    print ("  %42s | %10s | %s" %  ("Label", "Checksum", "Name"))
    try:
        for channel in client.channel.listSoftwareChannels(key):
            details = client.channel.software.getDetails(key,channel['label'])
            if 'checksum_label' in details :
                print ("  %42s | %10s | %s" % (channel['label'], details['checksum_label'] ,channel['name']))
            else:
                print ("  %42s | %10s | %s" % (channel['label'], "" ,channel['name']))
    except:
            warnings.warn("error trying to list channels")
            raise

def select_channels(key):
    """Selects all channels that aren't RHEL4 or RHEL3 or don't have no checksum defined"""
    global client;
    channels = []
    for channel in client.channel.listSoftwareChannels(key):
        ch = client.channel.software.getDetails(key,channel['label'])
        if 'checksum_label' in ch and ch['checksum_label'] in ('sha256','sha1','sha384','sha512'):
            channels.append(ch['label'])
        elif 'checksum_label':
            print "unknown checksum "+ch['label']+" please report to maintainer"
        else:
            print "no checksum type - ignoring "+ch['label']
    return channels

def regen_channel(key,force,channel=None):
    # this should be enough to ask the satellite to regenerate the yum cache - the repodata - but removing the /var/cache/rhn/repodata then running this might give better results (especially if need to force).
    if force: 
        print "removing previous content to force regeneration"
        import shutil,os
        folder = '/var/cache/rhn/repodata'
        if channel == None:
            for entry in os.listdir(folder):
                entry_path = os.path.join(folder,entry)
                if os.path.isdir(entry_path):
                    setback_repomd_timestamp(entry_path)
        else:
            setback_repomd_timestamp(os.path.join(folder,channel))
    if channel == None:
        print "requesting global regeneration of the repodata"
        for entry in select_channels(key):
            try:
                client.channel.software.regenerateYumCache(key,entry)
                print "successfully queued "+entry
            except:
                warnings.warn("error trying to request the repodata regeneration for "+entry)
                pass
        try:
            client.channel.software.regenerateNeededCache(key)
            print "errata and package cache for all systems has been regenerated"
        except:
            warnings.warn("an exception occured durring the regenerateNeededCache call!")
            raise
    else:
        print "requesting that the repodata would be regenerated for "+channel
        try:
            client.channel.software.regenerateYumCache(key,channel)
            print "repodata should regenerate over the next 15 minutes for "+channel
        except:
            warnings.warn( "error trying to request the repodata regeneration for "+channel)
            raise
        try:
            client.channel.software.regenerateNeededCache(key,channel)
            print "errata and package cache for all systems subscribed to channel "+channel+" has been regenerated"
        except:
            warnings.warn( "an exception occured durring the regenerateNeededCache call!")
            raise
 
def setback_repomd_timestamp(repocache_path):
    repomd_file = (repocache_path + '/repomd.xml')
    stat_info = os.stat(repomd_file)
    mtime = stat_info[stat.ST_MTIME]
    new_mtime = mtime - 3600
    try:
        os.utime(repomd_file, (new_mtime, new_mtime))
    except OSError, e:
        warnings.warn("error setting back timestamp on %s: %s" % (repomd_file, e.strerror))
        warnings.warn("if the file does not exist ignore this error")
        pass

def regen_channel_db(key,channels=(), clean_db=False):
    """Inserts into the database the taskomatic jobs. requires to be run on the satellite or import will fail"""
    import sys
    sys.path.append('/usr/share/rhn/')
    #TODO: replace this by a file read test
    #TODO: use the taskomatic module instead to do the db operation
    try:
        #import server.repomd.repository as repository
        import server.rhnChannel as rhnChannel
        import common.rhnConfig as rhnConfig
        import server.rhnSQL as rhnSQL
    except ImportError:
        # this changed for 5.5
        import spacewalk.server.rhnChannel as rhnChannel
        import spacewalk.common.rhnConfig as rhnConfig
        import spacewalk.server.rhnSQL as rhnSQL

    rhnConfig.initCFG()
    rhnSQL.initDB()

    if clean_db:
        h = rhnSQL.prepare("DELETE FROM rhnRepoRegenQueue")
        h.execute()
        rhnSQL.commit();
    h = rhnSQL.prepare("INSERT INTO rhnRepoRegenQueue (id, CHANNEL_LABEL, REASON, BYPASS_FILTERS, FORCE) VALUES (rhn_repo_regen_queue_id_seq.nextval, :channel , 'repodata regeneration script','Y', 'Y')")
    for label in channels:
        h.execute(channel=label)
        print "channel "+label+" has been queued for regeneration"
    rhnSQL.commit();
    #now clean the needed cache to make sure all systems see their updates properly
    try:
        client.channel.software.regenerateNeededCache(key)
        print "errata and package cache for all systems has been regenerated"
    except:
        warnings.warn("an exception occured durring the regenerateNeededCache call!")
        raise 
    pass

def main(version):
    global client;
    parser = optparse.OptionParser("%prog -c channelname|-l|-a [-f]\n Requests to a satellite that a channel's repodata is regenerated\n satellite 5.3 requires that you use --db or --cleandb\n RHEL4 channels (and anterior) do not need their repodata to be generated to work.", version=version)
    parser.add_option("-l", "--list", dest="listing", help="List all channels and quit", action="store_true")
    parser.add_option("-c", "--channel", dest="channel", help="Label of the channel to querry regeneration for")
    parser.add_option("-a", "--all", action="store_true",dest="regen_all",help="Causes a global regeneration instead of just one channel")
    parser.add_option("-f", "--force", action="store_true",dest="force_operation",help="Forces the operation ; can only work if the script is run on the satellite itself",default=False)
    parser.add_option("--db", action="store_true", dest="use_db", help="Use the database instead of the api ; can only be used from the satellite itself. Implies --force",default=False)
    parser.add_option("--cleandb", action="store_true", dest="clean_db", help="Get rid of the pending actions before adding the new ones. implies --db and force.", default=False)
    parser.add_option("--url", dest="saturl",default=None, help="URL of the satellite api, e.g. https://satellite.example.com/rpc/api or http://127.0.0.1/rpc/api. Facultative")
    parser.add_option("--user", dest="satuser",default=None, help="username to use with the satellite. Should be admin of the organization owning the channels. Faculative")
    parser.add_option("--password", dest="satpwd",default=None, help="password of the user. Will be asked if not given")
    parser.add_option("--org", dest="satorg", default="baseorg", help="name of the organization to use - design the section of the config file to use")
    (options, args) = parser.parse_args()
    if options.listing:
        key = session_init(options.satorg , {"url" : options.saturl, "login" : options.satuser, "password" : options.satpwd})
        print_channels(key)
        client.auth.logout(key)
    elif options.use_db or options.clean_db:
        if not options.channel and not options.regen_all:
            parser.error('no channel mentioned')
        elif options.regen_all:
            key = session_init(options.satorg , {"url" : options.saturl, "login" : options.satuser, "password" : options.satpwd})
            regen_channel_db(key,select_channels(key), options.clean_db)
        else:
            key = session_init(options.satorg , {"url" : options.saturl, "login" : options.satuser, "password" : options.satpwd})
            regen_channel_db(key,[options.channel],options.clean_db)
    elif options.regen_all:
        key = session_init(options.satorg , {"url" : options.saturl, "login" : options.satuser, "password" : options.satpwd})
        regen_channel(key,options.force_operation)
        client.auth.logout(key)
    elif options.channel:
        key = session_init(options.satorg , {"url" : options.saturl, "login" : options.satuser, "password" : options.satpwd})
        regen_channel(key,options.force_operation,options.channel)
        client.auth.logout(key)
    else:
        parser.error('no action given')

#calls start here
if __name__=="__main__":
    main(__version__)
