@bootstrap
Feature: HA bootstrap process - init and join

  Scenario: Init cluster service on node "hanode1"
    Given   Cluster service is "stopped" on "local"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "local"
    And     Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "local"
    And     Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
