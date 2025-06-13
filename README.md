# miniOSM

A minimal OpenStreetMap server, intended as a shim for use online editing tools on a XML local export. 

```
# Serve an data over the network, read only
python minisom.py /path/to/data.xml

# Serve an data over the network, read/write
python minisom.py /path/to/data.xml -o /path/to/data.xml
```

A few warnings: 

It does not perform any authentication or sanity checks.
Creating backups or using external version control is highly recommended.

It also does not track the changes made to the data. Making multiple edits at once can break things. 
There is also no way to sync the changes to an upstream server.
Only use it if you have no intention of uploading your changes to the public map. 
