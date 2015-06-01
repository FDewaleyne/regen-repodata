#!/usr/bin/python

####
#
# Meant to help debug repodata generation issues ; this script will query the regeneration of the repodata through api or through an entry in the db.
#
####
__author__ = "Felix Dewaleyne"
__credits__ = ["Felix Dewaleyne"]
__license__ = "GPL"
__version__ = "4.1.0"
__maintainer__ = "Felix Dewaleyne"
__email__ = "fdewaley@redhat.com"
__status__ = "dev"

##
# will work for 5.6+
##

###
# To the extent possible under law, Red Hat, Inc. has dedicated all copyright to this software to the public domain worldwide, pursuant to the CC0 Public Domain Dedication.
# This software is distributed without any warranty.  See <http://creativecommons.org/publicdomain/zero/1.0/>.
###

import xmlrpclib, sys, getpass, ConfigParser, os, optparse, re
# import stat as well for the repodata file time edit

#global variables
client = None;
SATELLITE_LOGIN = None;
config = ConfigParser.ConfigParser()
config.read(['.satellite', os.path.expanduser('~/.satellite'), '/etc/sysconfig/rhn/satellite'])

# this will initialize a session and return its key.
# for security reason the password is removed from memory before exit, but we want to keep the current username.
def session_init(orgname='baseorg', settings={}):
    """initiates the connection to the api"""
    global client
    global config
    global SATELLITE_LOGIN
    global satver
    if 'url' in settings and not settings['url'] == None:
        SATELLITE_URL = settings['url']
    elif config.has_section('default') and config.has_option('default', 'url'):
        SATELLITE_URL = config.get('default', 'url')
    else:
        sys.stderr.write("enter the satellite url, such as https://satellite.example.com/rpc/api")
        sys.stderr.write("\n")
        SATELLITE_URL = raw_input().strip()
    #format the url if a part is missing
    if re.match('^http(s)?://[\w\-.]+/rpc/api', SATELLITE_URL) == None:
        if re.search('^http(s)?://', SATELLITE_URL) == None:
            SATELLITE_URL = "https://"+SATELLITE_URL
        if re.search('/rpc/api$', SATELLITE_URL) == None:
            SATELLITE_URL = SATELLITE_URL+"/rpc/api"
    if 'login' in settings and not settings['login'] == None:
        SATELLITE_LOGIN = settings['login']
    elif config.has_section(orgname) and config.has_option(orgname, 'username'):
        SATELLITE_LOGIN = config.get(orgname, 'username')
    else:
        sys.stderr.write("Login details for %s\n\n" % SATELLITE_URL)
        sys.stderr.write("Login: ")
        SATELLITE_LOGIN = raw_input().strip()
    if 'password' in settings and not settings['password'] == None:
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
    #fetch the version of satellite in use - set to None if this call generates an error
    try:
        satver = client.api.systemVersion()
        print "satellite version "+satver
    except:
        satver = None
        print "unable to detect the version"
        pass
    return key

def validate_channel(key, channel):
    """validates or not the usage of a channel"""
    ch = client.channel.software.getDetails(key, channel['label'])
    #if 'checksum_label' in ch and ch['checksum_label'] in ('sha256','sha1','sha384','sha512'):
    #updated the test to not use a finite list of checksums but rather only check if there is one
    if ch.get('checksum_label', None) != None:
        return True
    else:
        return False

def select_channels(key):
    """Selects all channels that aren't RHEL4 or RHEL3 or don't have no checksum defined"""
    global client
    channels = []
    for channel in client.channel.listSoftwareChannels(key):
        if validate_channel(key, channel):
            channels.append(channel['label'])
            print "channel "+channel['label']+" validated"
        else:
            sys.stderr.write("channel "+channel['label']+" ignored - no checksum type\n")
    return channels

def get_repomd_date(channel):
    """returns the date of the repomd file"""
    repo_path = "/var/cache/rhn/repodata/%s/repomd.xml" % (channel)
    if os.path.isfile(repo_path):
        if os.path.isfile(repo_path+".new"):
            print "repodata is being created for %s" % (channel)
        return os.path.getmtime(repo_path)
    else:
        #there is no repodata
        return None

def parse_cache(key, channel):
    """checks that a given channel is in the repodata cache & get the last build date, outputing the info"""
    global client
    global channels
    db_build_date = client.channel.software.getChannelLastBuildById(key, channels['label'])
    repomd_date = get_repomd_date(channel)
    #TBC
    
#global definition added with this script
channels = {}
def define_channels(key):
    """pulls all the software channels into a global list with their id associated. Only uses the list of channels and the info that can be pulled from it."""
    global client
    global channels

    #TBC

def main(version):
    """the main functoin of the program"""
    global client
    parser = optparse.OptionParser("%prog [-c channelname]\n Checks the last date the repodata was generated at for a channel or for all the channels.\nNeeds to be ran from he satellite itself.", version=version)
    parser.add_option("-c", "--channel", dest="channel", help="Label of the channel to querry regeneration for")
    # connection options
    connect_group = optparse.OptionGroup(parser, "Connection options", "Not required unless you want to bypass the details of ~/.satellite, .satellite or /etc/sysconfig/rhn/satellite or simply don't want to be asked the settings at run time")
    connect_group.add_option("--url", dest="saturl", default=None, help="URL of the satellite api, e.g. https://satellite.example.com/rpc/api or http://127.0.0.1/rpc/api ; can also be just the hostname or ip of the satellite. Facultative.")
    connect_group.add_option("--user", dest="satuser", default=None, help="username to use with the satellite. Should be admin of the organization owning the channels. Faculative.")
    connect_group.add_option("--password", dest="satpwd", default=None, help="password of the user. Will be asked if not given and not in the configuration file.")
    connect_group.add_option("--org", dest="satorg", default="baseorg", help="name of the organization to use - design the section of the config file to use. Facultative, defaults to %default")
    parser.add_option_group(connect_group)
    (options, args) = parser.parse_args()
    if options.channel != None :
        key = session_init(options.satorg, {"url" : options.saturl, "login" : options.satuser, "password" : options.satpwd})
        parse_cache(key, options.channel)
        client.auth.logout(key)
    else:
        key = session_init(options.satorg, {"url" : options.saturl, "login" : options.satuser, "password" : options.satpwd})
        parse_all_cache(key)
        client.auth.logout(key)

#calls start here
if __name__ == "__main__":
    main(__version__)
