**AI/ML Cybersecurity Lab 04 – Threat Hunting with Clustering Concepts**

**Overview**

In this lab, I used Splunk Enterprise to perform threat hunting using clustering concepts commonly found in artificial intelligence and machine learning. Unlike traditional signature-based detection, clustering techniques group similar activities together and help identify unusual behavior that may represent previously unknown threats or suspicious activity.

The dataset contains network connection information, including source and destination IP addresses, destination ports, protocols, connection counts, unique destinations, data transfer volumes, DNS activity, failed login attempts, geographic locations, and behavior groups. By analyzing these features, I can identify patterns of normal network activity and distinguish them from behaviors associated with reconnaissance, command-and-control communications, or other suspicious activities.\
\
This lab introduces clustering, an unsupervised machine learning technique widely used in cybersecurity threat hunting. Instead of relying on predefined attack signatures, clustering groups similar activities based on their characteristics and highlights behaviors that differ significantly from the majority of network traffic.

The primary Artificial intelligence/Machine learning concepts used in this lab include:

Unsupervised Learning\
Clustering\
Behavioral Pattern Analysis\
Outlier Detection\
Threat Hunting\
Network Traffic Analysis\
\
**Real-World Relevance**

Threat hunting using clustering techniques is commonly used by Security Operations Centers (SOCs) to identify suspicious behavior that may not trigger traditional security alerts. Security analysts use clustering to detect reconnaissance activity, abnormal network communications, lateral movement, and command-and-control traffic by identifying groups of events that differ from normal operational behavior.

In this lab, I will use Splunk Enterprise to analyze network activity, identify behavior clusters, investigate potential threats, and apply AI/ML concepts to support proactive threat hunting.\
\
**Objectives**

The objectives of this lab are to:

- Identify clusters of similar network behavior.

- Detect potential reconnaissance and scanning activity.

- Analyze network traffic patterns using clustering concepts.

- Identify outlier source IP addresses.

- Investigate abnormal connection behavior.

- Examine DNS and failed login activity.

- Prioritize suspicious behavior groups for further investigation.

**Dataset**

**File name:** threat_hunting_clustering_dataset.csv

Please refer to image # 1 in the repository.

**Fields**

timestamp

src_ip

dest_ip

dest_port

protocol

connection_count

unique_destinations

bytes_sent

dns_queries

failed_logins

country

behavior_group

**Uploading verification**

Please refer to image # 2 in the repository.

**Verification of indexed dataset into Splunk of 60 events**

Using the query:

index=network sourcetype=clustering_hunt
| table timestamp src_ip dest_ip dest_port protocol connection_count unique_destinations bytes_sent dns_queries failed_logins country behavior_group\
\
I queried the entire dataset after indexing to verify that all **60 events** were successfully ingested into Splunk Enterprise. The results display the complete set of network events, including timestamps, source and destination IP addresses, ports, protocols, connection counts, unique destinations, data transfer volumes, DNS activity, failed login attempts, geographic locations, and behavior groups. For demonstration purposes, only the first **5 events** are shown in the screenshot, while the complete dataset contains **60 events** used throughout this lab.

Please refer to images # 3 and 4 in the repository.

**Confirmation the dataset distribution**

Using the query:

index=network sourcetype=clustering_hunt

| stats count by behavior_group

Please refer to image # 5 in the repository.

This dataset consists of four distinct behavior groups representing different types of network activity. These behavior groups will be analyzed throughout this lab to identify patterns, detect outliers, and investigate suspicious activity using clustering concepts and AI/ML threat hunting techniques.


| **Behavior Group**            | **Events** |
|-------------------------------|------------|
| normal_web_activity           | 20         |
| admin_management_activity     | 12         |
| recon_scanning_activity       | 14         |
| suspicious_beaconing_activity | 14         |


**1. Which behavior groups exist in the dataset?**

index=network sourcetype=clustering_hunt\
\| stats count by behavior_group\
\| sort - count

AI/ML Concept:

Cluster Discovery

Please refer to image # 6 in the repository.

4 behavior groups exist in dataset\
.normal_web_activity\
. recon_scanning_activity\
. suspicious_beaconing_activity\
. admin_management_activity

**2. Which source IP addresses generated the most connections?**

index=network sourcetype=clustering_hunt\
\| stats sum(connection_count) as total_connections by src_ip\
\| sort - total_connections

AI/ML Concept:

Outlier Identification

Please refer to images # 7 and 8 in the repository.

The source IP addresses generating the highest number of connections included:

| **Source IP** | **Total Connections** |
|---------------|-----------------------|
| 10.0.1.11     | 77                    |
| 10.0.1.8      | 73                    |
| 10.0.0.27     | 59                    |
| 10.0.1.13     | 45                    |
| 10.0.0.14     | 39                    |

**3. Which source IPs communicated with the highest number of unique destinations?**

index=network sourcetype=clustering_hunt\
\| stats max(unique_destinations) as unique_destinations by src_ip\
\| sort - unique_destinations

AI/ML Concept:

Reconnaissance Detection

Please refer to images # 9 and 10 in the repository.


| **Source IP** | **Unique Destinations** |
|---------------|-------------------------|
| 198.51.100.30 | 85                      |
| 198.51.100.26 | 81                      |
| 198.51.100.72 | 79                      |
| 198.51.100.41 | 77                      |
| 198.51.100.65 | 71                      |

**4. Which countries generated the highest number of network connections**?

index=network sourcetype=clustering_hunt\
\| stats sum(connection_count) as total_connections by country\
\| sort - total_connections

AI/ML Concept:

Behavioral Grouping

Please refer to image # 11 in the repository.


| **Country** | **Total Connections** |
|-------------|-----------------------|

| Unknown | 2,619 |
|---------|-------|

| China | 1,659 |
|-------|-------|

| Russia | 1,309 |
|--------|-------|

| USA | 408 |
|-----|-----|

| UK  | 118 |
|-----|-----|

| Canada | 100 |
|--------|-----|

The **Unknown** category generated the highest number of network connections, followed by **China** and **Russia**. These countries produced substantially more connection activity than the USA, UK, and Canada.

However, a high number of connections alone does **not** confirm malicious activity. Large connection volumes may result from legitimate administrative tasks, automated services, or normal business operations. Therefore, additional investigation is required to determine whether this traffic is associated with suspicious behavior.\
This query represents an initial stage of behavioral analysis. Rather than identifying attacks directly, it highlights countries responsible for the highest network activity. In AI/ML-assisted threat hunting, these results help analysts identify areas that may warrant further investigation.

The next step is to filter the dataset by suspicious behavior groups—such as **recon_scanning_activity** and **suspicious_beaconing_activity**—to determine whether these high-volume countries are also associated with potentially malicious activity. This transition from overall activity to suspicious clusters is a key concept in AI-driven threat hunting.

**5. Which countries are associated with the highest volume of suspicious activity?**

index=network sourcetype=clustering_hunt\
\| search behavior_group="recon_scanning_activity" OR behavior_group="suspicious_beaconing_activity"\
\| stats sum(connection_count) as suspicious_connections by country\
\| sort - suspicious_connections

Please refer to image # 12 in the repository.

The countries associated with the highest suspicious connection volume were **Unknown**, **China**, and **Russia**.

**6. Which destination ports are most frequently targeted?**

index=network sourcetype=clustering_hunt\
\| stats count by dest_port\
\| sort - count

AI/ML Concept:

Service Profiling

Please refer to image # 13 in the repository.

The most frequently targeted destination ports were:

**80 (HTTP)** 14 events\
**443 (HTTPS)** 12 events\
**8080 (Alternative HTTP/Web Applications)** 8 events\
**22 (SSH)** 5 events\
**5985 (Windows Remote Management)** 5 events\
**8443 (Alternative HTTPS)** 5 events\
\
The dataset shows activity across several categories of network services:

**Web Services:** Ports **80**, **443**, **8080**, and **8443** indicate web applications and web servers.\
**Remote Administration:** Ports **22 (SSH)**, **3389 (RDP)**, and **5985 (WinRM)** suggest remote management activity.\
**Legacy Services:** Ports **21 (FTP)** and **23 (Telnet)** appear less frequently but may require attention because they are older protocols that can introduce security risks if still in use.\
**File Sharing:** Port **445 (SMB)** appears only once, indicating minimal file-sharing activity in this dataset.\
From a threat-hunting perspective, attackers commonly scan web services and remote administration ports because they often provide entry points into an organization's network. High activity on these ports does not necessarily indicate malicious behavior, but it helps identify services that should receive closer monitoring.\
This query supports **behavioral clustering** by identifying common service usage patterns.

Frequent access to **80** and **443** is generally expected.

Concentrated activity on **22**, **3389**, **5985**, **8080**, or **8443** may represent a distinct behavioral cluster, especially when combined with high connection counts, many unique destinations, or suspicious geographic origins.\
Rather than treating a single port as malicious, clustering algorithms evaluate the **combination of ports, traffic volume, destinations, and behavioral characteristics** to distinguish normal administrative activity from reconnaissance or attack behavior. This is a key advantage of AI-assisted threat hunting over traditional rule-based detection.

**7. Which behavior group transferred the most data?**

index=network sourcetype=clustering_hunt\
\| stats sum(bytes_sent) as total_bytes by behavior_group\
\| sort - total_bytes

AI/ML Concept:

Cluster Comparison

Please refer to image # 14 in the repository.

The **suspicious_beaconing_activity** behavior group transferred the largest amount of data, with **61,010,869 bytes**, making it the highest-volume behavior group in the dataset.\
\
The results show a significant difference in data transfer volume between the four behavioral clusters.\
The results show a significant difference in data transfer volume between the four behavioral clusters.

**. suspicious_beaconing_activity** generated by far the highest amount of network traffic, transferring more than **61 million bytes**.

**. admin_management_activity** produced the second-highest volume, which is expected because administrative operations often involve remote management and system maintenance.

**. normal_web_activity** generated moderate traffic consistent with everyday user activity.

**. recon_scanning_activity** transferred the least amount of data, which aligns with reconnaissance behavior because scanning typically involves many connection attempts but relatively little data exchange. This pattern is consistent with real-world cyberattacks, where reconnaissance generates numerous small requests, while command-and-control or malware communications often involve sustained and larger data transfers.\
\
**Artificial intelligence/Machine learning insight\

This query demonstrates how clustering helps analysts compare the characteristics of different behavioral groups instead of evaluating isolated events.

An AI/ML model can recognize that:

**. Reconnaissance** is typically characterized by **high connection counts**, **many unique destinations**, and **low data transfer**.

**. Beaconing or command-and-control activity** often exhibits **repeated communications** combined with **higher cumulative data transfer**.

**. Administrative activity** forms a separate cluster because it legitimately transfers more data while following predictable management patterns.

**. Normal user activity** remains within an expected range and serves as the baseline.

By comparing these behavioral clusters, analysts can prioritize investigations based on patterns that differ significantly from normal operations rather than relying solely on predefined attack signatures. This illustrates one of the primary advantages of AI/ML-driven threat hunting in modern Security Operations Centers (SOCs).

**8. Which behavior group generated the most DNS activity?**

index=network sourcetype=clustering_hunt\
\| stats sum(dns_queries) as total_dns_queries by behavior_group\
\| sort - total_dns_queries

AI/ML Concept:

Pattern Recognition

Please refer to image # 15 in the repository.

The **suspicious_beaconing_activity** behavior group generated the highest DNS activity with **1,625 DNS queries**, significantly exceeding all other behavior groups.\
\
The results reveal a substantial difference in DNS activity among the four behavioral clusters.

**. suspicious_beaconing_activity** generated **1,625 DNS queries**, making it the most active DNS behavior in the dataset.

**. normal_web_activity** produced **342 DNS queries**, which is consistent with everyday web browsing.

**. recon_scanning_activity** generated relatively few DNS queries because network scanning typically targets IP addresses and services rather than relying heavily on DNS resolution.

**. admin_management_activity** generated the fewest DNS queries, reflecting predictable internal administrative operations.

The unusually high DNS activity associated with the **suspicious_beaconing_activity** cluster suggests behavior that warrants additional investigation.


**Artificial intelligence/ Machine learning Insight**


This query demonstrates how AI/ML models can use **DNS behavior as a feature** when clustering network activity.

Rather than relying on DNS activity alone, clustering algorithms evaluate multiple characteristics together, including:

**. DNS query volume**
**. Connection frequency**
**. Data transfer size**
**. Number of unique destinations**
**. Geographic location**
**. Destination ports**

When these features are analyzed collectively, AI/ML models can distinguish **normal web browsing**, **administrative activity**, **reconnaissance**, and **suspicious beaconing** without relying solely on predefined attack signatures. In this dataset, the exceptionally high DNS query volume makes the **suspicious_beaconing_activity** cluster stand out as the highest-priority candidate for further investigation.

**9. Which behavior groups generated the most failed logins?**

index=network sourcetype=clustering_hunt\
\| stats sum(failed_logins) as total_failed_logins by behavior_group\
\| sort - total_failed_logins

AI/ML Concept:

Threat Hunting Prioritization

Please refer to image # 16 in the repository.

The **recon_scanning_activity** behavior group generated the highest number of failed login attempts, with **49 failed logins**, followed by **suspicious_beaconing_activity** with **30 failed logins**.\
\
The results indicate that authentication failures are concentrated within the suspicious behavior groups.

**. recon_scanning_activity** produced the highest number of failed logins. This aligns with attacker behavior during the reconnaissance phase, where authentication services are often probed using invalid credentials to identify accessible systems or weak accounts.

**. suspicious_beaconing_activity** generated the second-highest number of failed logins, suggesting that compromised systems may also be attempting unauthorized authentication as part of ongoing malicious activity.

**. normal_web_activity** and **admin_management_activity** showed relatively few failed logins, which is consistent with expected user behavior and legitimate administrative operations.

This distribution suggests that failed login activity is a valuable indicator for prioritizing investigations into reconnaissance-related behavior.

**10. Which events look most like reconnaissance activity?**

index=network sourcetype=clustering_hunt\
\| sort - unique_destinations\
\| table src_ip country unique_destinations connection_count behavior_group

AI/ML Concept:

Cluster Outliers

Please refer to images # 17 and 18 in the repository.

| **Source IP** | **Country** | **Unique Destinations** | **Connections** | **Behavior Group** |
|----|----|----|----|----|
| 198.51.100.30 | Russia | 85 | 139 | recon_scanning_activity |
| 198.51.100.26 | Unknown | 81 | 499 | recon_scanning_activity |
| 198.51.100.72 | Russia | 79 | 167 | recon_scanning_activity |
| 198.51.100.41 | Unknown | 77 | 406 | recon_scanning_activity |
| 198.51.100.65 | China | 71 | 277 | recon_scanning_activity |

The events most consistent with reconnaissance activity originated from the **198.51.100.x** address range. These systems contacted **29 to 85 unique destination hosts** and were all classified within the **recon_scanning_activity** behavior group.\
\
Several indicators strongly suggest reconnaissance behavior:

**.** Every high-ranking event belongs to the **recon_scanning_activity** cluster.

**.** The source IP addresses communicate with an unusually large number of unique destination systems.

**.** Many of these hosts also generate hundreds of network connections.

**.** The activity is associated primarily with the **Unknown**, **China**, and **Russia** country categories.

In contrast, normal web activity communicates with only **6–8 unique destinations**, representing expected user behavior.

This combination of high connection counts and extensive host discovery is characteristic of network reconnaissance and port-scanning operations commonly observed during the early stages of cyberattacks.

**11. Which behavior groups appear most suspicious and should be investigated first?**

index=network sourcetype=clustering_hunt\
\| stats sum(connection_count) as connections sum(unique_destinations) as destinations sum(bytes_sent) as bytes sum(failed_logins) as failed_logins by behavior_group

Please refer to image # 19 in the repository.

The two behavior groups that should be prioritized for investigation are:

**1. recon_scanning_activity**\
**2. suspicious_beaconing_activity\
\**
Each suspicious behavior group exhibits a different threat profile:

### recon_scanning_activity

This behavior group generated:

**. 4,450 network connections** (highest)\
**. 852 unique destinations** (highest)\
**. 49 failed login attempts** (highest)\
**. Relatively low data transfer**

These characteristics are consistent with reconnaissance and network discovery, where an attacker probes many systems and services while exchanging relatively little data.

### suspicious_beaconing_activity

This behavior group generated:

**. 61,010,869 bytes transferred** (highest)\
**. 1,137 network connections**\
**. 30 failed login attempts**\
**. Moderate number of unique destinations**

These characteristics resemble command-and-control (C2) beaconing or persistent malware communications, where infected systems repeatedly communicate with external infrastructure and transfer significant amounts of data.

### Normal Activity

The **normal_web_activity** and **admin_management_activity** groups remained within expected operational ranges and did not exhibit the same combination of suspicious behavioral indicators.

## AI/ML Insight

This final investigation demonstrates one of the fundamental principles of AI-driven threat hunting:

**No single indicator determines whether activity is malicious.**

Instead, AI/ML models evaluate multiple behavioral features simultaneously, such as:

**.** Connection volume\
**.** Number of unique destinations\
**.** Data transfer volume\
**.** Failed login frequency\
**.** DNS activity\
**.** Geographic patterns\
**.** Destination ports

By combining these features, clustering algorithms separate events into distinct behavioral groups. In this lab:

**. recon_scanning_activity** formed a cluster characterized by **high connection counts**, **extensive host discovery**, and **numerous failed logins**, making it indicative of reconnaissance.

**. suspicious_beaconing_activity** formed a separate cluster distinguished by **very high data transfer**, **heavy DNS activity**, and **persistent outbound communications**, making it representative of potential malware or command-and-control behavior.

This illustrates how modern SOC platforms use AI/ML to prioritize investigations based on **behavioral patterns** rather than relying solely on known attack signatures. It is a practical example of **unsupervised learning**, where similar events are grouped together and analysts investigate the clusters that deviate most from normal network behavior.

## Conclusion

This lab demonstrated how clustering concepts can enhance threat hunting by identifying groups of related behaviors instead of isolated events. By analyzing multiple behavioral features together, I was able to distinguish between normal web activity, legitimate administrative operations, reconnaissance scanning, and suspicious beaconing. This approach mirrors how AI/ML-assisted SOC platforms help analysts focus on the most significant threats, enabling faster and more effective investigations into previously unknown or evolving attack techniques.


