Feature: HA bootstrap process

  Scenario: Show init help messages
    Given   Have "crm" command
    When    Run "crm cluster init --help" on "local"
    Then    Got right outputs

  Scenario: No overwrite ssh key
    Given   Cluster is not running on "local"
    And     Already have ssh key
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "local"
    Then    Cluster is running on "local"
    And     ssh key have no changes

  Scenario: Overwrite ssh key
    Given   Cluster is not running on "local"
    And     Already have ssh key
    When    Run "crm cluster init -y" on "local"
    Then    Cluster is running on "local"
    And     ssh key have changed

  Scenario: No overwrite ssh key but append to authorized_keys
    Given   Cluster is not running on "local"
    And     Already have ssh key
    And     "/root/.ssh/authorized_keys" not exists
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "local"
    Then    Cluster is running on "local"
    And     ssh key have no changes
    And     "/root/.ssh/authorized_keys" exists
