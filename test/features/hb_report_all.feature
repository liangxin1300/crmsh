@hb_report
Feature: hb_report functional test

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Run hb_report on new environment
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Try "hb_report"
    Then    Except "ERROR: hanode1#Master: Could not figure out a list of nodes; is this a cluster node?"
    When    Run "hb_report -n hanode1" on "hanode1"
    Then    Default hb_report tar file created
    When    Remove default hb_report tar file
    When    Run "hb_report -n hanode2" on "hanode1"
    Then    Default hb_report tar file created
    When    Remove default hb_report tar file

  @clean
  Scenario: Verify hb_report handle files contain non-utf-8 characters
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    # touch file contain non utf-8 character
    When    Run "echo 'abc#$%%^' | iconv -f UTF-8 -t UTF-16 > /opt/text_non_utf8" on "hanode1"
    And     Run "hb_report -E /opt/text_non_utf8 report1" on "hanode1"
    Then    File "text_non_utf8" in "report1.tar.bz2"
    When    Run "rm -f report1.tar.bz2" on "hanode1"

    # -f and -t option
    When    Run "hb_report -f 2019 /opt/report" on "hanode1"
    Then    "/opt/report.tar.bz2" created
    And     "/opt/report.tar.bz2" include essential files for "hanode1 hanode2"
    When    Try "hb_report -f 2020 -t 2019"
    Then    Except "ERROR: hanode1#Master: Start time must be before finish time"
    When    Try "hb_report -f xxxx"
    Then    Except multiline:
      """
      ERROR: parse_time xxxx: ('Unknown string format:', 'xxxx')
      ERROR: hanode1#Master: Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"
      """
    When    Try "hb_report -f 2020/01/01 -t wrong"
    Then    Except multiline:
      """
      ERROR: parse_time wrong: ('Unknown string format:', 'wrong')
      ERROR: hanode1#Master: Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"
      """

    # -d and -Z option
    When    Run "hb_report -d" on "hanode1"
    Then    Default hb_report directory created
    When    Run "hb_report -f 2019 -d /opt/report" on "hanode1"
    Then    "/opt/report" created
    And     "/opt/report" include essential files for "hanode1 hanode2"
    When    Try "hb_report -d /opt/report"
    Then    Except "ERROR: hanode1#Master: Destination directory /opt/report exists, please cleanup or use -Z option"
    When    Run "hb_report -d -Z /opt/report" on "hanode1"
    Then    "/opt/report" created

    # -n option
    When    Run "hb_report -f 2019 -n hanode2 onenode" on "hanode1"
    Then    "onenode.tar.bz2" created
    And     "onenode.tar.bz2" include essential files for "hanode2"
