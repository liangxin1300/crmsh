@qdevice
Feature: corosync qdevice/qnetd options validate

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Option "--qnetd-hostname" use the same node
    When    Try "crm cluster init --qnetd-hostname=hanode1"
    Then    Except "ERROR: cluster.init: host for qnetd must be a remote one"

  @clean
  Scenario: Option "--qnetd-hostname" use hanode1's IP
    When    Try "crm cluster init --qnetd-hostname=10.10.10.2"
    Then    Except "ERROR: cluster.init: host for qnetd must be a remote one"

  @clean
  Scenario: Option "--qnetd-hostname" use unknown hostname
    When    Try "crm cluster init --qnetd-hostname=error-node"
    Then    Except "ERROR: cluster.init: host "error-node" is unreachable"

  @clean
  Scenario: Service ssh on qnetd node not available
    When    Try "crm cluster init --qnetd-hostname=node-without-ssh"
    Then    Except "ERROR: cluster.init: ssh service on "node-without-ssh" not available"

  @clean
  Scenario: Option "--qdevice-port" set wrong port
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-port=1"
    Then    Except "ERROR: cluster.init: invalid qdevice port range(1024 - 65535)"

  @clean
  Scenario: Option "--qdevice-algo" set wrong value
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-algo=wrongalgo"
    Then    Except "ERROR: cluster.init: invalid qdevice algorithm(ffsplit/lms)"

  @clean
  Scenario: Option "--qdevice-tie-breaker" set wrong value
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-tie-breaker=wrongtiebreaker"
    Then    Except "ERROR: cluster.init: invalid qdevice tie_breaker(lowest/highest/valid_node_id)"

  @clean
  Scenario: Option "--qdevice-tls" set wrong value
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-tls=wrong"
    Then    Except "ERROR: cluster.init: invalid qdevice tls(on/off/required)"

  @clean
  Scenario: Option "--qdevice-heuristics" set wrong value
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-heuristics='ls /opt'"
    Then    Except "ERROR: cluster.init: commands for heuristics should be absolute path"
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-heuristics='/bin/not_exists_cmd /opt'"
    Then    Except "ERROR: cluster.init: command /bin/not_exists_cmd not exists"

  @clean
  Scenario: Option "--qdevice-heuristics-mode" set wrong value
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-heuristics='/usr/bin/ls' --qdevice-heuristics-mode="xxx""
    Then    Except "ERROR: cluster.init: invalid heuristics mode(on/sync/off)"

  @clean
  Scenario: Option "--qnetd-hostname" is required by other qdevice options
    When    Try "crm cluster init --qdevice-port=1234"
    Then    Except multiple lines
      """
      usage: init [options] [STAGE]
      crm: error: Option --qnetd-hostname is required if want to configure qdevice
      """

  @clean
  Scenario: Option --qdevice-heuristics is required if want to configure heuristics mode
    When    Try "crm cluster init --qnetd-hostname=qnetd-node --qdevice-heuristics-mode="on""
    Then    Except multiple lines
      """
      usage: init [options] [STAGE]
      crm: error: Option --qdevice-heuristics is required if want to configure heuristics mode
      """

  @clean
  Scenario: Node for qnetd is a cluster node
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Try "crm cluster init --qnetd-hostname=hanode2 -y --no-overwrite-sshkey"
    Then    Except multiple lines
      """"
      ERROR: cluster.init: host for qnetd must be a non-cluster node
      Cluster service already successfully started on this node
      If you still want to use qdevice, change another host or disable and stop cluster service on hanode2
      Then run command "crm cluster init qdevice --qnetd-hostname={qnetd_addr}"
      This command will setup qdevice separately while keep cluster running
      """
    And     Cluster service is "started" on "hanode1"
    When    Run "crm cluster stop" on "hanode2"

  @clean
  Scenario: Node for qnetd not installed corosync-qnetd
    Given   Cluster service is "stopped" on "hanode2"
    When    Try "crm cluster init --qnetd-hostname=hanode2 -y --no-overwrite-sshkey"
    Then    Except multiple lines
      """"
      ERROR: cluster.init: Package "corosync-qnetd" not installed on hanode2
      Cluster service already successfully started on this node
      If you still want to use qdevice, install "corosync-qnetd" on hanode2
      Then run command "crm cluster init qdevice --qnetd-hostname={qnetd_addr}"
      This command will setup qdevice separately while keep cluster running
      """
    And     Cluster service is "started" on "hanode1"

  @clean
  Scenario: Run qdevice stage on inactive cluster node
    Given   Cluster service is "stopped" on "hanode1"
    When    Try "crm cluster init qdevice --qnetd-hostname=qnetd-node"
    Then    Except "ERROR: cluster.init: Cluster is inactive - can't run qdevice stage"

  @clean
  Scenario: Run qdevice stage but miss "--qnetd-hostname" option
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm cluster init qdevice"
    Then    Except "ERROR: cluster.init: qdevice related options are missing (--qnetd-hostname option is mandatory, find for more information using --help)"
