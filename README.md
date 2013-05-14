regen\_repodata
==============

Script used to cause the events that will trigger a regeneration of repodata in satellite.

~~~
Usage: regen_repodata.py -c channelname|-l|-a [-f]
 Requests to a satellite that a channel's repodata is regenerated
 satellite 5.3 requires that you use --db or --cleandb
 RHEL4 channels (and anterior) do not need their repodata to be generated to work.

Options:
  -h, --help            show this help message and exit
  -l, --list            List all channels and quit
  -c CHANNEL, --channel=CHANNEL
                        Label of the channel to querry regeneration for
  -a, --all             Causes a global regeneration instead of just one
                        channel
  -f, --force           Forces the operation ; can only work if the script is
                        run on the satellite itself
  --db                  Use the database instead of the api ; can only be used
                        from the satellite itself. Implies --force
  --cleandb             Get rid of the pending actions before adding the new
                        ones. implies --db and force.
  --url=SATURL          URL of the satellite api, e.g.
                        https://satellite.example.com/rpc/api or
                        http://127.0.0.1/rpc/api. Facultative
  --user=SATUSER        username to use with the satellite. Should be admin of
                        the organization owning the channels. Faculative
  --password=SATPWD     password of the user. Will be asked if not given
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
