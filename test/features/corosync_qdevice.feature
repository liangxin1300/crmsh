Feature: Management corosync qdevice/qnetd
  Note: hostname "qnetd-node", "hanode1" and "hanode2" are defined in .travis.yml.
  "hanode1" and "hanode2" are cluster nodes, "qnetd-node" is qnetd node.

  Scenario: Setup qdevice/qnetd during init process
    Given   Packages should be installed
      | pkg_name         |
      | corosync         |
      | corosync-qdevice |
    And     Cluster is not running on "local"
    And     Service "corosync-qdevice" is not running on "local"
    When    Run "crm cluster init --qdevice=qnetd-node -y" on "local"
    Then    Cluster is running on "local"
    And     Service "corosync-qdevice" is running on "local"

  Scenario: Second node join and start qdevice
    Given   Cluster is not running on "hanode2"
    And     Service "corosync-qdevice" is not running on "hanode2"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster is running on "hanode1 hanode2"
    And     Service "corosync-qdevice" is running on "hanode2"
      
  Scenario: Setup qdevice/qnetd after init process
    Given   Cluster is running on "local"
    And     Service "corosync-qdevice" is not running on "local"
    When    Run "crm cluster init qdevice --qdevice=qnetd-node -y" on "local"
    Then    Cluster is running on "local"
    And     Service "corosync-qdevice" is running on "local"

  Scenario: Setup qdevice/qnetd on a two nodes cluster
    Given   Cluster is running on "hanode1 hanode2"
    And     Service "corosync-qdevice" is not running on "local"
    And     Service "corosync-qdevice" is not running on "hanode2"
    When    Run "crm cluster init qdevice --qdevice=qnetd-node -y" on "local"
    Then    Service "corosync-qdevice" is running on "local"
    And     Service "corosync-qdevice" is running on "hanode2"

  Scenario: Remove qdevice on a two nodes cluster
    Given   Cluster is running on "hanode1 hanode2"
    And     Service "corosync-qdevice" is running on "local"
    And     Service "corosync-qdevice" is running on "hanode2"
    When    Run "crm cluster remove --qdevice -y" on "local"
    Then    Cluster is running on "hanode1 hanode2"
    And     Service "corosync-qdevice" is not running on "local"
    And     Service "corosync-qdevice" is not running on "hanode2"
