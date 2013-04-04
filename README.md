regen_repodata
==============

Script used to cause the events that will trigger a regeneration of repodata in satellite.

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
