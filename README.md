regen\-repodata
==============

Script used to cause the events that will trigger a regeneration of repodata in satellite.

a link to download the script from the latest raw is available : [http://bit.ly/regen-repodata](http://bit.ly/regen-repodata)

~~~
Usage: regen-repodata.py -c channelname|-l|-a [-f]
 Requests to a satellite that a channel's repodata is regenerated
 satellite 5.3 requires that you use --db or --cleandb
 RHEL4 channels (and anterior) do not need their repodata to be generated to work.

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -l, --list            List all channels and quit
  -c CHANNEL, --channel=CHANNEL
                        Label of the channel to querry regeneration for
  -a, --all             Causes a global regeneration instead of just one
                        channel

  Local options:
    Require to run the script directly on the satellite if used

    -f, --force         Forces the operation ; can only work if the script is
                        run on the satellite itself
    --db                Use the database instead of the api ; implies --force
    --cleandb           Get rid of the pending actions before adding the new
                        ones ; also deletes existing metadata stored in the
                        database for the channel(s) used (5.4.0+ only).
                        implies --db and --force.
    --cleancache        Cleans the needed cache and exits. Useful after
                        running against --db

  Connection options:
    Not required unless you want to bypass the details of ~/.satellite,
    .satellite or /etc/sysconfig/rhn/satellite or simply don't want to be
    asked the settings at run time

    --url=SATURL        URL of the satellite api, e.g.
                        https://satellite.example.com/rpc/api or
                        http://127.0.0.1/rpc/api ; can also be just the
                        hostname or ip of the satellite. Facultative.
    --user=SATUSER      username to use with the satellite. Should be admin of
                        the organization owning the channels. Faculative.
    --password=SATPWD   password of the user. Will be asked if not given and
                        not in the configuration file.
    --org=SATORG        name of the organization to use - design the section
                        of the config file to use. Facultative, defaults to
                        baseorg
~~~
**NOTE** : `--db`  still requires access to the api to avoid adding channels that should not be generated (channels with no checksum type)

**NOTE2** : it is possible to store the connection credentials in a configuration file : `.satellite` or `~/.satellite` or `/etc/sysconfig/rhn/satellite`.

the format of the file should be

    [default]
    url=https://yoursatellitefqdn/RPC/API
    [baseorg]
    username=satellitelogin
    password=satellitepassword

note that the content in `[baseorg]` isn't required ; if `[default]` is missing the configuration file will be ignored.
