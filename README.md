well ig its time i release this, this was a project made by me and dear sk4ller (if you are seeing this sk4ller, this is only being released due to the fact someone else has decided to leech the project (mr anti geek to be specfic) and sold copies behind my back and i simply do not trust him)

so how does this work?

we can take a quick dip into obregistercallbacks in windows internal 

link : [URL="https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks"]https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks[/URL]

more links : [URL="https://www.unknowncheats.me/forum/anti-cheat-bypass/148364-obregistercallbacks-and-countermeasures.html"]https://www.unknowncheats.me/forum/anti-cheat-bypass/148364-obregistercallbacks-and-countermeasures.html[/URL]

what we are doing here is basically just disabling the call backs without restoring them and then we can simply r/w memory safely with anything (you can use process hacker and try to dump strings to test / view memory)

Good luck pasting this, i will leave a built version of the driver that is signed in the source x64 path.

to use this just create a service using the following

"sc create driver binpath="path/kernel.sys" type=kernel"

then just sign it with a leaked cert and start it, enjoy.
