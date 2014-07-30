shrike
======
From http://en.wikipedia.org/wiki/Shrike
"Shrikes are known for their habit of catching insects and small vertebrates and impaling their bodies on thorns, the spikes on barbed-wire fences or any available sharp point. This helps them to tear the flesh into smaller, more conveniently-sized fragments, and serves as a cache so that the shrike can return to the uneaten portions at a later time."

What it does:
Resolve URL or refering site based on alert or http log match in suricata eve log. Perform a very simple and dumb hash of either 4 tuple or ip pair and search a configured amount of in memory buffered http log entries. Submit url,referer,landing to Cuckoo as url task. This is alpha code. Shrike takes a single argument to a json configuration file. See code for sample suricata eve config. 
