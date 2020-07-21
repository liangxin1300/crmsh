## Qdevice in corosync

#### Motivation/User story
* Users want the cluster node hosting HANA master to survive split-brain

#### What is corosync?
* The communication layer of HA cluster
* Mainly cares about cluster membership, message passing and quorum

#### What is Qdevice(Quorum device)?
* One feature/component in corosync
* A third-party arbitration device for the cluster
* To allow a cluster to sustain more node failures by voting

#### How does Qdevice help user?
* Qdevice has an external api called `heuristics`, which will run commands or custom scripts on each node on split-brain happen
* Qdevice will vote according to `heuristics`'s return code
* We write a script to tell which node was running HANA master
* Then the node hosting HANA master will got the vote(has quorum) and survive split-brain
