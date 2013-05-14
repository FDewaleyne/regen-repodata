#!/usr/bin/python

#author : Felix Dewaleyne

# version : 2.0.2
##
# will work for 5.4 and 5.5
# will work for 5.3 only if using the database options (--db --cleandb)
##History
# 1.2 : fixed genation of the repodata for all channels and moved to using warnings.warn for warnings
# 1.2.1 : it can't work for 5.3 as the main call used isn't part of the api.
# 1.2.2 : inclusion of patches suggested (change the timestamps instead of removing the repodata)
# 2.0.0 : adding options to use the DB instead of the api (sat 5.3 and ways to clear the jobs)
# 2.0.1 : last bugs ironed out with queueing all channels using the new filter
# 2.0.2 : bug fixed where regenerating one channel with --db would not properly be treated.
# 2.0.2b : fixed typo in usage info
# 2.0.3 : moving url to default

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
def session_init(orgname='baseorg'):
    global client;
    global config;
    global SATELLITE_LOGIN;
    if config.has_section("default") and config.has_section(orgname) and config.has_option(orgname,'username') and config.has_option(orgname,'password') and config.has_option('default','url'):
        SATELLITE_LOGIN = config.get(orgname,'username')
        SATELLITE_PASSWORD = config.get(orgname,'password')
        SATELLITE_URL = config.get('default','url')
    else:
        if not config.has_section("default") and not config.has_option('default','url'):
            sys.stderr.write("enter the satellite url, such as https://satellite.example.com/rpc/api")
            sys.stderr.write("\n")
            SATELLITE_URL = raw_input().strip()
        else:
            SATELLITE_URL = config.get('default','url')
        sys.stderr.write("Login details for %s\n\n" % SATELLITE_URL)
        sys.stderr.write("Login: ")
        SATELLITE_LOGIN = raw_input().strip()
        # Get password for the user
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
    print ("%40s | %s" %  ("Label", "Name"))
    try:
        for channel in client.channel.listSoftwareChannels(key):
            print ("%40s | %s" % (channel['label'] ,channel['name']))
    except:
            warnings.warn("error trying to list channels")
            raise

def select_channels(key):
    """Selects all channels that aren't RHEL4 or RHEL3 or don't have no checksum defined"""
    global client;
    channels = []
    for channel in client.channel.listSoftwareChannels(key):
        ch = client.channel.software.getDetails(key,channel['label'])
        #does this have a checksum? if it's sha256 or md5sum let's process the channel
        if ch['checksum_label'] in ('sha256','md5sum'):
            channels.append(ch['label'])
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

def main():
    global client;
    parser = optparse.OptionParser("%prog -c channelname|-l|-a [-f]\n Requests to a satellite that a channel's repodata is regenerated\n satellite 5.3 requires that you use --db or --cleandb\n RHEL4 channels (and anterior) do not need their repodata to be generated to work.")
    parser.add_option("-l", "--list", dest="listing", help="List all channels and quit", action="store_true")
    parser.add_option("-c", "--channel", dest="channel", help="Label of the channel to querry regeneration for")
    parser.add_option("-a", "--all", action="store_true",dest="regen_all",help="Causes a global regeneration instead of just one channel")
    parser.add_option("-f", "--force", action="store_true",dest="force_operation",help="Forces the operation ; can only work if the script is run on the satellite itself",default=False)
    parser.add_option("--db", action="store_true", dest="use_db", help="Use the database instead of the api ; can only be used from the satellite itself. Implies --force",default=False)
    parser.add_option("--cleandb", action="store_true", dest="clean_db", help="Get rid of the pending actions before adding the new ones. implies --db and force.", default=False)
    (options, args) = parser.parse_args()
    if options.listing:
        key = session_init()
        print_channels(key)
        client.auth.logout(key)
    elif options.use_db or options.clean_db:
        if not options.channel and not options.regen_all:
            parser.error('no channel mentioned')
        elif options.regen_all:
            key = session_init()
            regen_channel_db(key,select_channels(key), options.clean_db)
        else:
            key = session_init()
            regen_channel_db(key,[options.channel],options.clean_db)
    elif options.regen_all:
        key = session_init()
        regen_channel(key,options.force_operation)
        client.auth.logout(key)
    elif options.channel:
        key = session_init()
        regen_channel(key,options.force_operation,options.channel)
        client.auth.logout(key)
    else:
        parser.error('no action given')

#calls start here
if __name__=="__main__":
    main()
