@crm_report
Feature: crm report functional test for verifying bugs

  Tag @clean means need to stop cluster service if the service is available

  Background: Setup a two nodes cluster
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: Verify crm report related bugs
  # Scenario: Collect ra trace files in python way (bsc#1189641)
    When    Run "crm configure primitive d Dummy op monitor interval=3s" on "hanode1"
    And     Run "crm resource trace d monitor" on "hanode1"
    And     Wait "10" seconds
    And     Run "crm report report" on "hanode1"
    Then    File "d.monitor.\d\d\d\d-.*" in "report.tar.bz2"
    When    Remove previously created files

  # Scenario: Include archived logs and /var/log/messages(bsc#1148873)
    When    Write multi lines to file "/var/log/log1"
      """
      2020-09-06T11:41:17+0800 node1 log message line1
      2020-09-06T11:42:19+0800 node1 log message line2
      2020-09-06T11:42:20+0800 node1 log message line3
      """
    And     Run "xz /var/log/log1" on "hanode1"
    And     Register "/var/log/log1.xz" to remove
    When    Write multi lines to file "/var/log/log1"
      """
      2020-09-06T11:42:21+0800 node1 log message line4
      2020-09-06T11:42:27+0800 node1 log message line5
      """
    And     Run "crm report -f 20200901 -E /var/log/log1 report1" on "hanode1"
    Then    File "log1" in "report1.tar.bz2"
    When    Run "tar jxf report1.tar.bz2" on "hanode1"
    And     Register "report1" to remove
    And     Run "cat report1/hanode1/log1" on "hanode1"
    Then    Expected multiple lines in output
      """
      2020-09-06T11:41:17+0800 node1 log message line1
      2020-09-06T11:42:19+0800 node1 log message line2
      2020-09-06T11:42:20+0800 node1 log message line3
      2020-09-06T11:42:21+0800 node1 log message line4
      2020-09-06T11:42:27+0800 node1 log message line5
      """
    When    Remove previously created files
    # archived irregular files
    When    Write multi lines to file "/tmp/text1"
      """
      This is line1
      This is line2
      This is line3
      """
    And     Run "xz /tmp/text1" on "hanode1"
    And     Register "/tmp/text1.xz" to remove
    When    Write multi lines to file "/tmp/text1"
      """
      This is line4
      This is line5
      """
    And     Run "crm report -f 20200901 -E /tmp/text1 report1" on "hanode1"
    Then    File "text1" in "report1.tar.bz2"
    When    Run "tar jxf report1.tar.bz2" on "hanode1"
    And     Register "report1" to remove
    And     Run "cat report1/hanode1/text1" on "hanode1"
    Then    Expected multiple lines in output
      """
      This is line1
      This is line2
      This is line3
      This is line4
      This is line5
      """
    When    Remove previously created files

  # Scenario: Collect corosync.log(bsc#1148874)
    When    Run "sed -i '/\s\+logfile:/d' /etc/corosync/corosync.conf" on "hanode1"
    When    Run "sed -i '/\s\+logfile:/d' /etc/corosync/corosync.conf" on "hanode2"
    And     Run "crm report report" on "hanode1"
    Then    File "corosync.log" not in "report.tar.bz2"
    When    Remove previously created files

    When    Run "sed -i '/to_logfile:/a logfile: /var/log/cluster/corosync.log' /etc/corosync/corosync.conf" on "hanode1"
    When    Run "sed -i '/to_logfile:/a logfile: /var/log/cluster/corosync.log' /etc/corosync/corosync.conf" on "hanode2"
    When    Run "crm corosync set logging.to_logfile yes" on "hanode1"
    When    Run "crm corosync set logging.to_logfile yes" on "hanode2"
    And     Run "crm cluster run \"crm cluster restart\"" on "hanode1"
    And     Wait "5" seconds
    And     Run "crm report report" on "hanode1"
    Then    File "corosync.log" in "report.tar.bz2"
    When    Remove previously created files

  # Scenario: crm report doesn't run if corosync.conf doesn't exist (bsc#1067456)
    When    Run "rm -f /etc/corosync/corosync.conf" on "hanode1"
    And     Run "rm -f /etc/corosync/corosync.conf" on "hanode2"
    And     Run "crm report" on "hanode1"
    Then    Default crm report tar file created
    When    Remove previously created files

  # Scenario: Get node's status flag file correctly (bsc#1106052)
    When    Run "crm report report1" on "hanode1"
    Then    File "HA_SERVICE_STOPPED" not in "report1.tar.bz2"
    And     File "HA_SERVICE_RUNNING" in "report1.tar.bz2"
    When    Remove previously created files
    And     Run "crm cluster run \"crm cluster stop\"" on "hanode1"
    When    Run "crm report report1" on "hanode1"
    Then    File "HA_SERVICE_STOPPED" in "report1.tar.bz2"
    And     File "HA_SERVICE_RUNNING" not in "report1.tar.bz2"
    When    Remove previously created files

  @clean
  Scenario: Replace sensitive data(bsc#1163581)
    # Set sensitive data TEL and password
    When    Run "crm node utilization hanode1 set TEL 13356789876" on "hanode1"
    When    Run "crm node utilization hanode1 set password qwertyui" on "hanode1"
    When    Run "crm report report" on "hanode1"
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R "qwertyui" report"
    # crm report mask passw.* by default
    # No password here
    Then    Expected return code is "1"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

    # mask password and ip address by using crm.conf
    When    Run "crm configure primitive ip2 IPaddr2 params ip=10.10.10.124" on "hanode1"
    And     Run "sed -i 's/; \[report\]/[report]/' /etc/crm/crm.conf" on "hanode1"
    And     Run "sed -i 's/; sanitize_rule = .*$/sanitize_rule = passw.*|ip.*:raw/g' /etc/crm/crm.conf" on "hanode1"
    And     Run "crm report report" on "hanode1"
    And     Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R -E "10.10.10.124|qwertyui" report"
    # No password here
    Then    Expected return code is "1"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

    # Do sanitize job, also for TEL
    When    Run "crm report -s -p TEL report" on "hanode1"
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R "qwertyui" report"
    # No password here
    Then    Expected return code is "1"
    When    Try "grep -R "13356789876" report"
    # No TEL number here
    Then    Expected return code is "1"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

    # disable sanitize
    When    Run "sed -i 's/; \[report\]/[report]/' /etc/crm/crm.conf" on "hanode1"
    And     Run "sed -i 's/sanitize_rule = .*$/sanitize_rule = /g' /etc/crm/crm.conf" on "hanode1"
    When    Run "crm report report" on "hanode1"
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R "qwertyui" report"
    # found password
    Then    Expected return code is "0"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"
