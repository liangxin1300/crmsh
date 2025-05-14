@bootstrap
Feature: Regression test for bootstrap bugs

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3

  @clean
  Scenario: Setup cluster with crossed network
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "iptables -A INPUT -i eth1 -s 10.89.0.0/24 -j DROP" on "hanode1"
    When    Run "iptables -A INPUT -i eth1 -s 10.89.0.0/24 -j DROP" on "hanode2"
    When    Run "crm cluster init -i eth0 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm cluster join -c hanode1 -i eth1 -y" on "hanode2"
    Then    Cluster service is "stopped" on "hanode2"
    And     Except "Cannot see peer node "hanode1", please check the communication IP" in stderr
    When    Run "crm cluster join -c hanode1 -i eth0 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
