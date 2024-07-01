# miniOSM

A minimal openstreetmap server, just about good enough to edit an xml data dump over a network.
Supports nodes and ways, does not support relations. Changes are applied immediately when uploaded, a dumpy changeset id is returned to keep software happy.

```
# Serve an data over the network, read only
python minisom.py /path/to/data.xml
# Serve an data over the network, read/write
# Backups are highly recomended, the software makes no attempt at authentication or sanity checking.
python minisom.py /path/to/data.xml -o /path/to/data.xml
```
