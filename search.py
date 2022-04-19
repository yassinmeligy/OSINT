#!/usr/bin/python3
import malwarelist
with open("sorted.txt") as f:
    for x in f:
        x = x.strip()
        malwarelist.lists(x)
      
f.close()



