#### About
This is the public repository for the Dynatrace CrowdStrike dashboard. The dashboard uses DQL and the Dynatrace entity model to pinpoint Windows servers impacted by the July 19, 2024 CrowdStrike issue. Please download the JSON for the dashboard and upload it into your Dynatrace Dashboards app in the gen3 platform.

#### 7/26/2024 Update - Dashboard for Dynatrace Managed
There is now a version of the dashboard that is compatible with Dynatrace Managed. You can download the JSON for this gen2 dashboard here: [Gen2](https://github.com/jwood1985/dynatrace-crowdstrike-dql/blob/main/CrowdStrike%20Host%20Analysis%20(Gen2).json). Please select `Windows` as your `Operating System` and, if necessary, select your `Host` name as a dynamic filter. Thank you to Pol de Lapparent (pol.de-lapparent@dynatrace.com) for the assistance on this!

![image](https://github.com/user-attachments/assets/cedc3548-ba36-4b4a-85e0-05d590fcd70f)

#### 7/22/2024 Update
I added in a field to detect whether a given host has **Bitlocker** on it. I also made a minor change to the DQL to grab the `Recently Restarted?` field more accurately.

```
fetch dt.entity.process_group_instance
  | fieldsAdd pgi_name=entity.name
  | filter contains(pgi_name,"crowdstrike",caseSensitive:false)
  | lookup 
  	[
          fetch dt.entity.process_group_instance
          | fieldsAdd host_id=belongs_to[dt.entity.host]
          | fieldsAdd runs
          | fieldsAdd metadata
          | fieldsAdd isDockerized
          | fieldsAdd awsNameTag
          | fieldsAdd pgi_id = id
          | fieldsAdd inbound_pgi=toString(called_by)
          | fieldsAdd outbound_pgi=toString(calls)
          | fieldsAdd pgi_name = entity.name
  	], sourceField:pgi_name, lookupField:pgi_name, prefix:"process."
  
  | lookup [
          fetch dt.entity.host
          | fieldsAdd host_name = entity.name
          | fieldsAdd monitoringMode
          | fieldsAdd osType
          | fieldsAdd lifetime
  ], sourceField:process.host_id, lookupField:id, prefix:"host."
  
  // Select only Windows hosts
  | filter host.osType=="WINDOWS"

  | lookup [
          fetch dt.davis.events
          | filter dt.source_entity.type == "host"
          | filter event.group_label=="Host or monitoring unavailable"
          | fieldsAdd endtime = event.end
          | fieldsAdd affected_ids = toString(affected_entity_ids)
          | parse `affected_ids`, """'[\"' LD:host_id '\"]'"""
  ], sourceField:process.host_id, lookupField: host_id, prefix:"events."

  // Determine whether the server has been unavailable and then restarted in the last 24 hrs
  // The "end" field in the host's lifetime should be within 5 minutes of the current time. 
  // If not, the host has not returned from its offline status.
  // Then look for hosts with an "unmonitored" or "unavailable" event. If that event occurred
  // in the last 24 hrs AND the server is back online after being offline, then the host 
  // is recently restarted.
  | fieldsAdd delta=toDouble((toLong(toTimestamp(now()))-toLong(toTimestamp(host.lifetime[end]))))/toDouble(1000000000*60)
  | fieldsAdd server_restarted_after_offline=if(delta<5,"YES",else:"NO")
  | fieldsAdd recent_restart_24hr = toLong(toTimestamp(now())) - toLong(toTimestamp(events.endtime))
  | fieldsAdd recent_restart=if((recent_restart_24hr<24*60*60*1000000000) AND (server_restarted_after_offline=="YES"),"YES",else:"NO")

  // Host lifetime from the first time the server was seen in Dynatrace
  | fieldsAdd `Lifetime (days)`=toDouble((toLong(toTimestamp(host.lifetime[end])))-toLong(toTimestamp(host.lifetime[start])))/toDouble((24*60*60*1000000000))
  
  // Add in field to check for Bitlocker-related processes
  | lookup 
	[
          fetch dt.entity.process_group_instance
          | fieldsAdd host_id=belongs_to[dt.entity.host]
          | filter contains(entity.name,"bitlocker",caseSensitive:false)
          | fieldsAdd pgi_name = entity.name
	], sourceField:process.host_id, lookupField:host_id, prefix:"bitlocker."

  | limit 10000
  
  // Apply filters
  | fieldsAdd tenantId=$TenantID
  | fieldsAdd host_filter=if($HostFilter=="ALL","",else:$HostFilter)
  | filter contains(host.host_name,host_filter,caseSensitive:false)
  | filter in(recent_restart,$RecentRestart)

  | fieldsAdd `Bitlocker Present?`=if(isNotNull(bitlocker.pgi_name),"YES",else:"NO")
  | fieldsAdd host_link = concat("https://",tenantId,".apps.dynatrace.com/ui/apps/dynatrace.classic.hosts/ui/entity/",host.id)
  | fields `Host`=host.host_name, `Process Name`=pgi_name, `Host Link`=host_link, `Recently Restarted?`=recent_restart, `Bitlocker Present?`
  | summarize count=count(), by:{`Host`, `Host Link`, `Bitlocker Present?`, `Recently Restarted?`}
  | sort `Bitlocker Present?` asc
  | fields `Host`, `Bitlocker Present?`, `Recently Restarted?`, `Host Link`
```
![image](https://github.com/user-attachments/assets/bd27a75a-dacc-488e-8050-5e4bc6b29473)

Questions? Please reach out to Dynatrace via the in UI chat or drop me a note at josh.wood@dynatrace.com.
