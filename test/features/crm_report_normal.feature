@crm_report
Feature: crm report functional test

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Run crm report on new environment, without cib.xml
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Try "crm report"
    Then    Except "hanode1: ERROR: Cannot figure out a list of nodes"
    When    Run "crm report -n hanode2 report" on "hanode1"
    Then    File "HA_SERVICE_RUNNING" not in "report.tar.bz2"
    Then    File "HA_SERVICE_STOPPED" in "report.tar.bz2"
    When    Remove previously created files

  @clean
  Scenario: Verify log file filter by time span
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    When    Write multi lines to file "/var/log/text_time_span"
      """
      Feb 01 08:57:29 node1 line1
      Feb 05 09:00:00 node1 line2
      Feb 15 09:00:00 node1 line3
      Feb 15 09:23:00 node1 line4
      Feb 15 09:45:00 node1 line5
      """
    # file not in time span
    When    Run "crm report -E /var/log/text_time_span -f "Jan01" -t "Jan31" report1" on "hanode1"
    Then    File "text_time_span" not in "report1.tar.bz2"

    # file content all in time span
    When    Run "crm report -E /var/log/text_time_span -f "Jan01" -t "Feb16" report2" on "hanode1"
    Then    File "text_time_span" in "report2.tar.bz2"
    When    Get "text_time_span" content from "report2.tar.bz2"
    Then    Expected multiple lines
      """
      Feb 01 08:57:29 node1 line1
      Feb 05 09:00:00 node1 line2
      Feb 15 09:00:00 node1 line3
      Feb 15 09:23:00 node1 line4
      Feb 15 09:45:00 node1 line5
      """

    # part of file content in time span
    When    Run "crm report -E /var/log/text_time_span -f "Jan01" -t "Feb10" report3" on "hanode1"
    Then    File "text_time_span" in "report3.tar.bz2"
    When    Get "text_time_span" content from "report3.tar.bz2"
    Then    Expected multiple lines
      """
      Feb 01 08:57:29 node1 line1
      Feb 05 09:00:00 node1 line2
      """

    # part of file content in time span
    When    Run "crm report -E /var/log/text_time_span -f "Feb15 09:00" -t "Feb15 09:43" report4" on "hanode1"
    Then    File "text_time_span" in "report4.tar.bz2"
    When    Get "text_time_span" content from "report4.tar.bz2"
    Then    Expected multiple lines
      """
      Feb 15 09:00:00 node1 line3
      Feb 15 09:23:00 node1 line4
      """

    # part of file content in time span
    When    Run "crm report -E /var/log/text_time_span -f "Feb15 09:01" -t "Feb27 09:43" report5" on "hanode1"
    Then    File "text_time_span" in "report5.tar.bz2"
    When    Get "text_time_span" content from "report5.tar.bz2"
    Then    Expected multiple lines
      """
      Feb 15 09:23:00 node1 line4
      Feb 15 09:45:00 node1 line5
      """
    When    Remove previously created files

  @clean
  Scenario: Verify crm report options
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    # from time after to time
    When    Try "crm report -f 2020 -t 2019"
    Then    Except "hanode1: ERROR: Start time must be before finish time"
    When    Try "crm report -f 2pm -t 1pm"
    Then    Except "hanode1: ERROR: Start time must be before finish time"
    # wrong format of from time
    When    Try "crm report -f xxx"
    Then    Except multiple lines
      """
      ERROR: parse_time xxx: Unknown string format: xxx
      hanode1: ERROR: Wrong time format: "xxx". Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"
      """
    # wrong format of to time
    When    Try "crm report -f 2020/01/01 -t wrong"
    Then    Except multiple lines
      """
      ERROR: parse_time wrong: Unknown string format: wrong
      hanode1: ERROR: Wrong time format: "wrong". Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"
      """
    # -b option
    When    Run "crm report -b 12d report" on "hanode1"
    Then    "report.tar.bz2" created
    And     "report.tar.bz2" include essential files for "hanode1 hanode2"
    When    Get "timespan.txt" content from "report.tar.bz2"
    Then    Expected "12 Days" in stdout
    When    Remove previously created files
    # wrong format of -b time
    When    Try "crm report -b 2019"
    Then    Except "hanode1: ERROR: Wrong format of -b option "2019" (valid examples: 30M; 12H; 10d; 2m; 1Y)"
    # -d and -Z option
    When    Run "crm report -d" on "hanode1"
    Then    Default crm report directory created
    When    Run "crm report -f 2019 -d /opt/report" on "hanode1"
    Then    "/opt/report" created
    And     "/opt/report" include essential files for "hanode1 hanode2"
    When    Try "crm report -d /opt/report"
    Then    Except "hanode1: ERROR: Destination directory "/opt/report" exists, please cleanup or use -Z option"
    When    Run "crm report -d -Z /opt/report" on "hanode1"
    Then    "/opt/report" created
    When    Remove previously created files
