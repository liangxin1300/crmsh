import os
import steps.utils as utils

CLUSTER_INIT_HELP_MESSAGE = '''Usage: init [options] [STAGE]

Options:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution, this is
                        destructive, especially during the "storage" stage,
                        and the SSH key will be overwritten unless with "--no-
                        overwrite-sshkey" option)
  -t TEMPLATE, --template=TEMPLATE
                        Optionally configure cluster with template "name"
                        (currently only "ocfs2" is valid here)
  -n NAME, --name=NAME  Set the name of the configured cluster.
  -N NODES, --nodes=NODES
                        Additional nodes to add to the created cluster. May
                        include the current node, which will always be the
                        initial cluster node.
  -S, --enable-sbd      Enable SBD even if no SBD device is configured
                        (diskless mode)
  -w WATCHDOG, --watchdog=WATCHDOG
                        Use the given watchdog device
  --no-overwrite-sshkey
                        Should be used with "-y" option to avoid SSH key be
                        overwritten

  Network configuration:
    Options for configuring the network and messaging layer.

    -i IF, --interface=IF
                        Bind to IP address on interface IF
    -u, --unicast       Configure corosync to communicate over unicast (UDP),
                        and not multicast. Default is multicast unless an
                        environment where multicast cannot be used is
                        detected.
    -A IP, --admin-ip=IP
                        Configure IP address as an administration virtual IP
    -M, --multi-heartbeats
                        Configure corosync with second heartbeat line
    -I, --ipv6          Configure corosync use IPv6
    --qdevice=QDEVICE   QDevice IP
    --qdevice-port=QDEVICE_PORT
                        QDevice port
    --qdevice-algo=QDEVICE_ALGO
                        QDevice algorithm
    --qdevice-tie-breaker=QDEVICE_TIE_BREAKER
                        QDevice algorithm

  Storage configuration:
    Options for configuring shared storage.

    -p DEVICE, --partition-device=DEVICE
                        Partition this shared storage device (only used in
                        "storage" stage)
    -s DEVICE, --sbd-device=DEVICE
                        Block device to use for SBD fencing
    -o DEVICE, --ocfs2-device=DEVICE
                        Block device to use for OCFS2 (only used in "vgfs"
                        stage)


Stage can be one of:
    ssh         Create SSH keys for passwordless SSH between cluster nodes
    csync2      Configure csync2
    corosync    Configure corosync
    storage     Partition shared storage (ocfs2 template only)
    sbd         Configure SBD (requires -s <dev>)
    cluster     Bring the cluster online
    vgfs        Create volume group and filesystem (ocfs2 template only,
                requires -o <dev>)
    admin       Create administration virtual IP (optional)

Note:
  - If stage is not specified, the script will run through each stage
    in sequence, with prompts for required information.
  - If using the ocfs2 template, the storage stage will partition a block
    device into two pieces, one for SBD, the remainder for OCFS2.  This is
    good for testing and demonstration, but not ideal for production.
    To use storage you have already configured, pass -s and -o to specify
    the block devices for SBD and OCFS2, and the automatic partitioning
    will be skipped.'''

def before_feature(context, feature):
    if feature.name == "HA bootstrap process":
        context.init_help_message = CLUSTER_INIT_HELP_MESSAGE
