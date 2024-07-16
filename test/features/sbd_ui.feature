@sbd
Feature: crm sbd ui test cases

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Syntax check for crm sbd
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    Given   Has disk "/dev/sda5" on "hanode1"
    Given   Has disk "/dev/sda6" on "hanode1"
    Given   Has disk "/dev/sda7" on "hanode1"
    Given   Has disk "/dev/sda8" on "hanode1"
    Given   Has disk "/dev/sda5" on "hanode2"
    Given   Has disk "/dev/sda6" on "hanode2"
    Given   Has disk "/dev/sda7" on "hanode2"
    Given   Has disk "/dev/sda8" on "hanode2"
    When    Try "crm sbd configure /dev/sda5"
    Then    Except "ERROR: pacemaker.service is not active"
    When    Run "crm cluster init -y" on "hanode1"
    And     Run "crm cluster join -c hanode1 -y" on "hanode2"
    And     Run ": > /etc/sysconfig/sbd" on "hanode1"
    And     Try "crm sbd configure watchdog-timeout=30"
    Then    Except "ERROR: No device specified"
    When    Run "crm cluster init sbd -s /dev/sda5 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"

    When    Try "crm sbd configure show sysconfig xxx"
    Then    Except "ERROR: Invalid argument"
    When    Try "crm sbd configure show testing"
    Then    Except "ERROR: Unknown argument: testing"
    When    Try "crm sbd configure"
    Then    Except "ERROR: No argument"
    When    Try "crm sbd configure testing"
    Then    Except "ERROR: Invalid argument: testing"
    When    Try "crm sbd configure watchdog-timeout=f"
    Then    Except "ERROR: Invalid timeout value: f"
    When    Try "crm sbd configure name=testing"
    Then    Except "ERROR: Unknown argument: name=testing"
    When    Try "crm sbd configure device=/dev/sda5 device=/dev/sda5"
    Then    Except "ERROR: Duplicate device"
    When    Try "crm sbd configure device=/dev/sda6 device=/dev/sda7 device=/dev/sda8"
    Then    Except "ERROR: sbd.configure: Maximum number of SBD device is 3"

  Scenario: sbd configure for diskbased sbd
    # Update disk metadata
    When    Run "crm sbd configure watchdog-timeout=30 msgwait-timeout=60" on "hanode1"
    Then    Run "crm sbd configure show disk_metadata|grep -E "watchdog.*30"" OK
    Then    Run "crm sbd configure show disk_metadata|grep -E "msgwait.*60"" OK
    # Add a sbd disk with the existing sbd metadata
    Given   Run "crm sbd configure show sysconfig|grep "SBD_DEVICE=/dev/sda5"" OK
    When    Run "crm -F sbd configure device=/dev/sda6" on "hanode1"
    Then    Run "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=\"/dev/sda5;/dev/sda6\""" OK
    Then    Run "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=\"/dev/sda5;/dev/sda6\""" OK on "hanode2"
    And     Run "crm sbd configure show disk_metadata |grep -A 8 '/dev/sda6'|grep -E "watchdog.*30"" OK
    And     Run "crm sbd configure show disk_metadata |grep -A 8 '/dev/sda6'|grep -E "msgwait.*60"" OK
    # Remove a sbd disk
    When    Run "crm sbd remove device=/dev/sda5" on "hanode1"
    Then    Run "crm sbd configure show sysconfig|grep "SBD_DEVICE=/dev/sda6"" OK
    Then    Run "crm sbd configure show sysconfig|grep "SBD_DEVICE=/dev/sda6"" OK on "hanode2"
    # Replace a sbd disk
    When    Run "crm -F sbd configure device=/dev/sda7" on "hanode1"
    Then    Run "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=\"/dev/sda6;/dev/sda7\""" OK
    Then    Run "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=\"/dev/sda6;/dev/sda7\""" OK on "hanode2"
    And     Run "crm sbd configure show disk_metadata |grep -A 8 '/dev/sda7'|grep -E "watchdog.*30"" OK
    And     Run "crm sbd configure show disk_metadata |grep -A 8 '/dev/sda7'|grep -E "msgwait.*60"" OK
    # Remove sbd from cluster
    When    Run "crm sbd remove" on "hanode1"
    And     Run "crm cluster restart --all" on "hanode1"
    Then    Service "sbd.service" is "stopped" on "hanode1"
    Then    Service "sbd.service" is "stopped" on "hanode2"

  Scenario: sbd configure for diskless sbd
    # Newly setup
    When    Run "crm sbd configure device=""" on "hanode1"
    Then    Expected "Diskless SBD requires cluster with three or more nodes." in stderr
    And     Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Resource "stonith:fence_sbd" not configured
    # Shoud not has any sbd device configured
    When    Try "crm sbd configure show sysconfig|grep -E "SBD_DEVICE=.+""
    Then    Expected return code is "1"
    # Remove sbd from cluster
    When    Run "crm sbd remove" on "hanode1"
    And     Run "crm cluster restart --all" on "hanode1"
    Then    Service "sbd.service" is "stopped" on "hanode1"
    Then    Service "sbd.service" is "stopped" on "hanode2"
