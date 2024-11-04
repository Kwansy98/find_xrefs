# find_xrefs
ida script for printing xrefs function call chains.

![](vscodeimages/2024-11-04-20-30-27.png)

![](vscodeimages/2024-11-04-20-30-57.png)

# Install

copy find_xrefs.py to ida plugin directory.

# Why

User xrefs chart is good, why write a plugin with the same function?

![](vscodeimages/2024-11-04-20-32-20.png)

Because graphical display is inconvenient for text search.

![](vscodeimages/2024-11-04-20-33-23.png)

Using find_xrefs, find xrefs for NtCreateThread, i can quickly find where it calls etw logging:

![](vscodeimages/2024-11-04-20-35-10.png)

