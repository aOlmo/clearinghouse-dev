# Modules to make available for convenience so the names are available in the
# ipython shell. Just a lazy way to not have to execute these lines individually
# in a new shell.
from clearinghouse.website.control import interface
from clearinghouse.common.api import backend
from clearinghouse.common.api import keydb
from clearinghouse.common.api import keygen
from clearinghouse.common.api import lockserver
from clearinghouse.common.api import maindb
from clearinghouse.common.api import nodemanager

# grab a few objects to play with
g = maindb.get_user('user0')
(v, v2) = maindb.get_available_wan_vessels(g, 2)[:2]

