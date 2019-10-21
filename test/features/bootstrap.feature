Feature: HA bootstrap process

  Scenario: Show init help messages
    Given   Have "crm" command
    When    Run "crm cluster init --help" on "local"
    Then    Got right outputs
