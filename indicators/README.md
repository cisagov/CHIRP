# Writing Indicators for CHIRP

------

## The basics

CHIRP reads from indicator files located in a folder named "Indicators" in
the current working directory. These indicator files are a very simple .yaml format.

Here is an example indicator file:

```yaml
---
name: "Equals IoC"
description: |
  "This is a test IoC intended to be used for testing
  the parsing of our evtx files and locate IoCs in the
  output of our parser."
confidence: 9 # 0-10
ioc_type: "events"
indicator:
  event_type: "Application"
  event_id: 1531
  security.user_id: '== S-1-5-18'
---
name: "REGEX Test IoC"
description: |
  "This IoC tests the regex functionality"
confidence: 3
ioc_type: "events"
indicator:
  event_type: "Application"
  provider.name: "~= .*Restart.*"
---
name: "NOT Test IoC"
description: "Testing our NOT operator"
confidence: 7
ioc_type: "events"
indicator:
  event_type: "Application"
  event: "!= ''"

```

- Individual IoCs are separated by three hyphens `---`.
- The `name` field is a simple readable name, this is how the IoC name will be
presented throughout the program and its reports.
- `description` should be detailed information about where the IoC is from and
why it is relevant. It is important to be descriptive so the fidelity of the IoC
is obvious.
- `confidence` is a value from 1 (being the lowest confidence) to 10 establishing
how likely this IoC is to be a false-positive. Indicators with a high likelihood
of being a false-positive should be at the low end of the scale.
- `ioc_type` is the name of the plugin that this indicator maps to. CHIRP ships
with four plugins - `events`, `registry`, `network`, and `yara`. Each of these plugins
has their own `indicator` field format, which can be found in their plugin
documentation below.

## Operators

CHIRP operators follow a simple format, leveraging the yaml's key: value construct.

```yaml
event.event_data.subject_user_sid: '== S-1-5-18'
```

In the above example, the indicator is looking for a key of
event.event_data.subject_user_sid that has a value equal (==) to S-1-5-18. This would
match on an artifact that looks like:

```json
{
   "event":{
      "system":{
         "provider":{
            "name":"Microsoft-Windows-Security-Auditing",
            "guid":"{54849625-5478-4994-a5ba-3e3b0328c30d}"
         },
         "event_id":{
            "qualifiers":"",
            "$":5379
         },
         "version":0,
         "level":0,
         "task":13824,
         "opcode":0,
         "keywords":"0x8020000000000000",
         "time_created":{
            "system_time":"2021-03-03 20:23:12.849279"
         },
         "event_record_id":59826,
         "correlation":{
            "activity_id":"{4ae6733c-06c2-0001-c673-e64ac206d701}",
            "related_activity_id":""
         },
         "execution":{
            "process_id":744,
            "thread_id":836
         },
         "channel":"Security",
         "computer":"DESKTOP-ONG02M0",
         "security":{
            "user_id":""
         }
      },
      "event_data":{
         "subject_user_sid":"S-1-5-18",
         "subject_user_name":"***",
         "subject_domain_name":"***",
         "subject_logon_id":"0x00000000000223c2",
         "target_name":"***",
         "type":0,
         "count_of_credentials_returned":1,
         "read_operation":"%%8100",
         "return_code":0,
         "process_creation_time":"2021-03-03 20:22:46.742149",
         "client_process_id":8364
      },
      "fields":{
         "time":1614820992.0,
         "host":"***",
         "source":"Security.evtx"
      }
   }
}
```

All operators work recursively, so if the previous example was simply given
`event: "== S-1-5-18"`, the same results would be achieved -- though less efficiently.

There are three operators:

- `==` - Which searches for a value **equal** to the search parameter
- `!=` - Which searches for a value **not equal** to the search parameter
- `~=` - Which uses a **regular expression** as its search parameter

Multiple operators specified in an indicator file will implicitly AND. For example,
for a registry key you can search `key: '== SecurityHealth'` and
`value: '%windir%\\system32\\SecurityHealthSystray.exe'`, which will only return
the registry key with that key *AND* value.

## Events Plugin

The events plugin has one required field, one optional field, and intakes `operators`.

```yaml
---
name: "Equals IoC"
description: |
  "This is a test IoC intended to be used for testing
  the parsing of our evtx files and locate IoCs in the
  output of our parser."
confidence: 9 # 0-10
ioc_type: "events"
indicator:
  event_type: "Security"
  event_id: 5379
  event.event_data.subject_user_sid: '== S-1-5-18'
```

Observe the `indicator` key:

- `event_type` ingests the evtx type, for example: Application, Security, and
System are all relevant event types.
- (optional) `event_id` intakes an event ID to search for. This is an optional
field but will result in the IoC only looking at that specific event ID, which
is helpful to limit CPU usage.
- Remaining fields follow `operators` format.

Below is an example events artifact matching the indicator:

```json
{
   "event":{
      "system":{
         "provider":{
            "name":"Microsoft-Windows-Security-Auditing",
            "guid":"{54849625-5478-4994-a5ba-3e3b0328c30d}"
         },
         "event_id":{
            "qualifiers":"",
            "$":5379
         },
         "version":0,
         "level":0,
         "task":13824,
         "opcode":0,
         "keywords":"0x8020000000000000",
         "time_created":{
            "system_time":"2021-03-03 20:23:12.849279"
         },
         "event_record_id":59826,
         "correlation":{
            "activity_id":"{4ae6733c-06c2-0001-c673-e64ac206d701}",
            "related_activity_id":""
         },
         "execution":{
            "process_id":744,
            "thread_id":836
         },
         "channel":"Security",
         "computer":"DESKTOP-ONG02M0",
         "security":{
            "user_id":""
         }
      },
      "event_data":{
         "subject_user_sid":"S-1-5-18",
         "subject_user_name":"***",
         "subject_domain_name":"***",
         "subject_logon_id":"0x00000000000223c2",
         "target_name":"***",
         "type":0,
         "count_of_credentials_returned":1,
         "read_operation":"%%8100",
         "return_code":0,
         "process_creation_time":"2021-03-03 20:22:46.742149",
         "client_process_id":8364
      },
      "fields":{
         "time":1614820992.0,
         "host":"***",
         "source":"Security.evtx"
      }
   }
}
```

> Note: We do not dictate this structure, this is the structure given by Microsoft
> for event logs. This format is inconsistent in that it varies by log type and event
> type. The only modification we make to the structure is using badgerfish to convert
> the XML to JSON and modify any CamelCase keys to snake_case. If you are confused
> about where to search in an event log, you can view this format by observing the
> log in Event Viewer.

## Registry Plugin

The registry plugin has one required field and intakes `operators`.

```yaml
---
name: "Equals IoC"
description: |
  "This is a test IoC intended to be used for testing
  the parsing of our registry files and locate IoCs in the
  output of our parser."
confidence: 9 # 0-10
ioc_type: "registry"
indicator:
  registry_key: "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  value: "== %windir%\\system32\\SecurityHealthSystray.exe"
  registry_type: "== REG_EXPAND_SZ"
```

`registry_key` is the only required field, which specifies which location in the
hive to search. Internally, chirp will enumerate keys and values at that hive
location, then search for matches to the `operators`.

Below is an example registry artifact matching the indicator:

```json
{
    "key": "SecurityHealth",
    "value": "%windir%\\system32\\SecurityHealthSystray.exe",
    "registry_type": "REG_EXPAND_SZ"
}
```

## Network Plugin

The network plugin has one required field.

```yaml
---
name: "Example Network IoC"
description: |
  "This is an example for the README."
confidence: 10 # 0-10
ioc_type: "network"
indicator:
  ips: |
    1.1.1.1
    127.0.0.1
    www.google.com
```

`ips` does not necessarily have to be an ip, but it will also accept domains.
The network plugin specifically queries the dns cache and netstat, seeing if
there are any matching values to ips.

Below is an example artifact matching the indicator:

```json
{
    "test": {
        "description": "blah",
        "confidence": 1,
        "matches": [
            "127.0.0.1",
            "0.0.0.0"
        ]
    }
}
```

## Yara Plugin

The yara plugin has two required fields.

```yaml
---
name: "Yara test IoC"
description: |
  "This IoC tests our yara capability"
confidence: 9 # 0-10
ioc_type: "yara"
indicator:
  files: "C:\\Program Files\\Git\\bin\\*"
  rule: |
    rule OffsetExample {
    strings:
      $mz = "MZ"
    condition:
      $mz at 0
    }
```

- `files` is a string of files or file paths to search in. Valid types in files
include: `"<file>", "<file_path>/*","<file>, <file_path>, <file>". The yara
plugin will glob on stars and split on commas, allowing easy specification of
multiple files or file paths.
- `rule` is the actual yara rule. This should be in the form of a string starting
on a new line after the pipe (`|`).

The rule value is somewhat finnicky, as it is not something native to CHIRP,
but a part of the `yara-python` module by VirusTotal. It may require some massaging
to get these rules to run properly.

Below is an example of a yara artifact matching the indicator:

```json
{
    "meta": "{}",
    "namespace": "default",
    "rule": "OffsetExample",
    "strings": "[(0, '$mz', b'MZ')]",
    "tags": "[]",
    "file": "C:\\Program Files\\Git\\bin\\bash.exe"
}
```
