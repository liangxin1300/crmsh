@bootstrap
Feature: HA bootstrap process - remove node

  Scenario: Remove peer node "hanode2"
    Given   Cluster service is "started" on "local"
    And     Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm cluster remove hanode2 -y" on "local"
    Then    Cluster service is "started" on "local"
    And     Cluster service is "stopped" on "hanode2"
    And     Online nodes are "hanode1"

  Scenario: Remove local node "hanode1"
    Given   Cluster service is "started" on "local"
    And     Online nodes are "hanode1"
    When    Run "crm cluster remove hanode1 -y --force" on "local"
    Then    Cluster service is "stopped" on "hanode1"
